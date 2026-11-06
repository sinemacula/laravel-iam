<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason as AuthenticationFailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\PasskeyGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PasskeyGatewayTests;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RegistersPasskeys;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\TestCase;

/**
 * Integration tests for MFA's passkey gateway running a passkey factor's
 * ceremonies through `laravel-authentication`'s passkeys (IAM-3.10), with every
 * adapter between the two members bound by this package's binding rule, as an
 * application gets them while its MFA application offers passkeys.
 *
 * A person registers a passkey for an MFA enrolment through
 * `laravel-authentication`, so it is one of their factors, and MFA then asks
 * for and verifies an assertion of it, signed by the virtual authenticator, as
 * a browser would: the ceremony is bound to the person's sign-in and purpose,
 * allows only the credentials MFA names among the person's own passkeys, and
 * answers what the assertion itself observed, or why it does not hold, in MFA's
 * terms. The assertion's writes join MFA's transaction, on MySQL and PostgreSQL
 * at READ COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyGatewayAdapter::class)]
final class PasskeyGatewayAdapterTest extends TestCase
{
    use ArrangesFactorChanges, BindsStrayRequests, MigratesMembers, PasskeyGatewayTests, RegistersPasskeys, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The credential id of the passkey factor, in unpadded base64url. */
    private const string CREDENTIAL = 'cGFzc2tleS1nYXRld2F5';

    /** @var string The credential id of a passkey factor stored after factors that list none. */
    private const string LATER_CREDENTIAL = 'bGF0ZXItZmFjdG9y';

    /** @var string The credential id of another passkey of the person's, a sign-in passkey only. */
    private const string OTHER_CREDENTIAL = 'c2lnbi1pbi1wYXNza2V5';

    /** @var string The credential id of a passkey of the person's on the admin guard's relying party. */
    private const string ADMIN_CREDENTIAL = 'YWRtaW4tcGFzc2tleQ';

    /** @var string A guard of the `jwt` driver with a relying party of its own. */
    private const string ADMIN_GUARD = 'admin';

    /** @var string The admin guard's relying party id. */
    private const string ADMIN_RELYING_PARTY = 'admin.iam.test';

    /** @var string The origin the admin guard's passkey ceremonies run on. */
    private const string ADMIN_ORIGIN = 'https://admin.iam.test';

    /** @var string The credential id of a passkey of the person's on the partner guard's relying party. */
    private const string PARTNER_CREDENTIAL = 'cGFydG5lci1wYXNza2V5';

    /** @var string A guard of the `jwt` driver whose MFA application offers no passkeys. */
    private const string PARTNER_GUARD = 'partner';

    /** @var string The partner guard's relying party id. */
    private const string PARTNER_RELYING_PARTY = 'partner.iam.test';

    /** @var string The origin the partner guard's passkey ceremonies run on. */
    private const string PARTNER_ORIGIN = 'https://partner.iam.test';

    /** @var string A guard of the `jwt` driver sharing the default guard's relying party. */
    private const string SHARED_GUARD = 'mobile';

    /** @var ?\Tests\Fixtures\Models\Person The person holding a passkey factor the kit's checks share. */
    private ?Person $kitPerson = null;

    /** @var ?\SineMacula\Laravel\Mfa\Proofs\ProofBinding The step-up of that person's sign-in the kit's checks share. */
    private ?ProofBinding $kitBinding = null;

    /**
     * Passkeys are available as a factor whenever the gateway is bound.
     *
     * @return void
     */
    public function testTheGatewayIsAvailable(): void
    {
        self::assertTrue($this->gateway()->isAvailable());
    }

    /**
     * Through MFA, on MySQL and PostgreSQL at both levels, an assertion of the
     * person's passkey factor is requested and verified, and steps the session
     * up with a proof of the factor, its user verification as observed.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAPasskeyFactorStepsTheSessionUpThroughMfa(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [, , $factor] = $this->passkeyFactor();

        $request = Mfa::requestAssertion(self::servedCaller(), $factor->id, Purpose::STEP_UP);

        self::assertTrue($request->hasStarted(), $request->reason->value ?? '');

        $result = Mfa::verify(self::servedCaller(), Submission::assertion($factor->id, $this->respond($request->options)), Purpose::STEP_UP);

        self::assertTrue($result->isVerified(), $result->detail ?? '');
        self::assertNotNull($result->proof);
        self::assertSame('passkey', $result->proof->method);
        self::assertSame($factor->id, $result->proof->reference);
        self::assertTrue($result->proof->properties->userVerification);
        self::assertSame($request->options['challenge'], $result->proof->challengeId);
        self::assertInstanceOf(AccessTokenResult::class, $result->completion());
        self::assertSame(0, self::storage()->transactionLevel());
    }

    /**
     * A request bound in the container never reaches the assertion: MFA hands
     * the gateway no client, so `laravel-authentication`'s passkey is used for
     * a client of which nothing is known, never for the client of the request
     * the container holds, and the assertion still verifies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundRequestNeverReachesTheAssertion(): void
    {
        [, , $factor] = $this->passkeyFactor();

        $caller  = self::servedCaller();
        $request = Mfa::requestAssertion($caller, $factor->id, Purpose::STEP_UP);
        $used    = [];

        self::assertTrue($request->hasStarted(), $request->reason->value ?? '');

        Event::listen(PasskeyUsed::class, static function (PasskeyUsed $event) use (&$used): void {
            $used[] = $event;
        });

        $this->bindStrayRequest();

        $result = Mfa::verify($caller, Submission::assertion($factor->id, $this->respond($request->options)), Purpose::STEP_UP);

        self::assertTrue($result->isVerified(), $result->detail ?? '');
        self::assertCount(1, $used);
        self::assertSame([null, null], [$used[0]->context->client->ip, $used[0]->context->client->userAgent]);
    }

    /**
     * The identity's registered passkeys are listed as `laravel-authentication`
     * holds them, oldest first, each once: a sign-in passkey among them, and
     * never a credential a factor of MFA's names that no passkey of the
     * identity's holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRegisteredPasskeysAreTheIdentitysPasskeys(): void
    {
        [$person, , $factor] = $this->passkeyFactor();

        $this->registerPasskey($person, self::OTHER_CREDENTIAL);
        Factor::query()->create([
            ...$factor->only(['authenticatable_type', 'authenticatable_id', 'type', 'application']),
            'credential_reference' => self::LATER_CREDENTIAL,
            'status'               => 'pending',
        ]);

        self::assertSame([self::CREDENTIAL, self::OTHER_CREDENTIAL], $this->gateway()->credentialIds($person));
        self::assertSame([], $this->gateway()->credentialIds($this->createPerson()));
    }

    /**
     * The passkeys on the relying party of each guard of the `jwt` driver whose
     * MFA application offers passkeys are listed, guard by guard in the order
     * they are declared, and a passkey of a relying party two guards share
     * once; a guard of the `jwt` driver whose application offers no passkeys,
     * declared before one that does, and a guard of any other driver, list
     * none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePasskeysOfEveryGuardOfferingPasskeysAreListed(): void
    {
        [$person] = $this->passkeyFactor();

        config()->set('auth.guards.' . self::SHARED_GUARD, ['driver' => 'jwt', 'provider' => 'people']);
        config()->set('auth.guards.' . self::PARTNER_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'people',
            'passkeys' => ['id' => self::PARTNER_RELYING_PARTY, 'origins' => [self::PARTNER_ORIGIN]],
        ]);
        config()->set('auth.guards.' . self::ADMIN_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'people',
            'passkeys' => ['id' => self::ADMIN_RELYING_PARTY, 'origins' => [self::ADMIN_ORIGIN]],
        ]);
        config()->set('auth.guards.panel', ['driver' => 'session', 'provider' => 'people']);
        self::offerPasskeysOn(self::SHARED_GUARD, self::ADMIN_GUARD, 'panel');

        $this->authenticator()->origin = self::ADMIN_ORIGIN;
        $this->registerPasskey($person, self::ADMIN_CREDENTIAL, guard: self::ADMIN_GUARD);

        $this->authenticator()->origin = self::PARTNER_ORIGIN;
        $this->registerPasskey($person, self::PARTNER_CREDENTIAL, guard: self::PARTNER_GUARD);

        self::assertSame([self::CREDENTIAL, self::ADMIN_CREDENTIAL], $this->gateway()->credentialIds($person));
    }

    /**
     * A guard of the `jwt` driver that uses no passkeys, so has no relying
     * party, as `laravel-authentication` allows, is never asked: the listing,
     * and through it MFA's offers and assertions, still work on the guard that
     * offers passkeys.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardThatUsesNoPasskeysLeavesTheListingWorking(): void
    {
        [$person, , $factor] = $this->passkeyFactor();

        config()->set('auth.guards.' . self::GUARD . '.passkeys', ['id' => self::RELYING_PARTY, 'origins' => [self::ORIGIN]]);
        config()->set('authentication.passkeys.relying_party.id', null);
        config()->set('auth.guards.' . self::PARTNER_GUARD, ['driver' => 'jwt', 'provider' => 'people']);

        self::assertSame([self::CREDENTIAL], $this->gateway()->credentialIds($person));
        self::assertSame([$factor->id], array_map(static fn (FactorSummary $offered): string => $offered->id, Mfa::offeredFactors(self::servedCaller())));

        $request = Mfa::requestAssertion(self::servedCaller(), $factor->id, Purpose::STEP_UP);

        self::assertTrue($request->hasStarted(), $request->reason->value ?? '');
    }

    /**
     * A guard of the `jwt` driver whose MFA application offers passkeys, with
     * no valid relying party, fails closed: the listing throws, as that guard's
     * ceremonies do.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardOfferingPasskeysWithNoValidRelyingPartyFailsClosed(): void
    {
        [$person] = $this->passkeyFactor();

        config()->set('auth.guards.' . self::ADMIN_GUARD, ['driver' => 'jwt', 'provider' => 'people', 'passkeys' => ['id' => '127.0.0.1']]);
        self::offerPasskeysOn(self::ADMIN_GUARD);

        $this->expectException(\InvalidArgumentException::class);

        $this->gateway()->credentialIds($person);
    }

    /**
     * The options handed out allow only the credentials MFA names among the
     * identity's own passkeys, under a challenge bound to the sign-in and the
     * purpose.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOptionsAllowOnlyTheCredentialsNamed(): void
    {
        [$person, $session] = $this->passkeyFactor();

        $this->registerPasskey($person, self::OTHER_CREDENTIAL);

        $options = $this->gateway()->requestAssertion($person, $this->bindingOf($person, $session), [self::CREDENTIAL]);

        self::assertSame(['challenge', 'options', 'expires_at'], array_keys($options));
        self::assertIsArray($options['options']);
        self::assertIsArray($options['options']['allowCredentials']);
        self::assertSame([self::CREDENTIAL], array_column($options['options']['allowCredentials'], 'id'));
    }

    /**
     * A request that would allow none of the identity's passkeys is refused,
     * with no challenge written: another identity's credential, an unknown one
     * and none at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestAllowingNoneOfTheIdentitysPasskeysIsRefused(): void
    {
        [$person, $session] = $this->passkeyFactor();

        $stranger = $this->createPerson();

        $this->registerPasskey($stranger, self::OTHER_CREDENTIAL);

        $challenges = DB::table('passkey_challenges')->count();

        foreach ([[self::OTHER_CREDENTIAL], ['dW5rbm93bg'], []] as $credentials) {
            $refusal = self::refusal(fn (): mixed => $this->gateway()->requestAssertion($person, $this->bindingOf($person, $session), $credentials));

            self::assertSame(FailureReason::NOT_FOUND, $refusal->reason);
        }

        self::assertSame($challenges, DB::table('passkey_challenges')->count());
    }

    /**
     * A ceremony bound to another identity than the one it is for is refused,
     * when requested and when verified.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACeremonyBoundToAnotherIdentityIsRefused(): void
    {
        [$person, $session] = $this->passkeyFactor();

        $binding  = $this->bindingOf($this->createPerson(), $session);
        $requests = [
            fn (): mixed => $this->gateway()->requestAssertion($person, $binding, [self::CREDENTIAL]),
            fn (): mixed => $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], ['challenge' => 'challenge', 'credential' => []]),
        ];

        foreach ($requests as $request) {
            self::assertSame(FailureReason::NOT_FOUND, self::refusal($request)->reason);
        }
    }

    /**
     * An assertion of the passkey factor verifies, answering the credential
     * that made it, what its own authenticator data showed and the challenge it
     * answered; its use joins the caller's transaction, so one rolled back
     * leaves the challenge to be answered again.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnAssertionVerifiesInsideTheCallersTransaction(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->passkeyFactor();

        $binding  = $this->bindingOf($person, $session);
        $options  = $this->gateway()->requestAssertion($person, $binding, [self::CREDENTIAL]);
        $response = $this->respond($options);

        $connection = self::storage();

        $connection->beginTransaction();

        $assertion = $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], $response);

        $connection->rollBack();

        self::assertInstanceOf(PasskeyAssertion::class, $assertion);
        self::assertSame(self::CREDENTIAL, $assertion->credentialId);
        self::assertSame($options['challenge'], $assertion->challengeId);
        self::assertTrue($assertion->properties->userPresence);
        self::assertTrue($assertion->properties->userVerification);
        self::assertTrue($assertion->properties->phishingResistance);
        self::assertNull(Passkey::query()->sole()->getAttribute('last_used_at'));

        self::assertInstanceOf(PasskeyAssertion::class, $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], $response));
        self::assertSame(FailureReason::REPLAYED, $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], $response));
    }

    /**
     * An assertion answering the ceremony's own challenge once it has expired
     * is `expired`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionOfAnExpiredChallengeIsExpired(): void
    {
        [$person, $session] = $this->passkeyFactor();

        $binding  = $this->bindingOf($person, $session);
        $response = $this->respond($this->gateway()->requestAssertion($person, $binding, [self::CREDENTIAL]));

        $this->travel(301)->seconds();

        self::assertSame(FailureReason::EXPIRED, $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], $response));
    }

    /**
     * An assertion answering a challenge made for another purpose of the same
     * sign-in does not hold for this one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionForAnotherPurposeDoesNotVerify(): void
    {
        [$person, $session] = $this->passkeyFactor();

        $options = $this->gateway()->requestAssertion($person, $this->bindingOf($person, $session, Purpose::SIGN_IN), [self::CREDENTIAL]);

        self::assertSame(FailureReason::EXPIRED, $this->gateway()->verifyAssertion($person, $this->bindingOf($person, $session), [self::CREDENTIAL], $this->respond($options)));
    }

    /**
     * An assertion made by a credential the verification does not allow, an
     * empty allowlist, and a response that is not one, never verify.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionOutsideTheAllowlistNeverVerifies(): void
    {
        [$person, $session] = $this->passkeyFactor();

        $binding  = $this->bindingOf($person, $session);
        $response = $this->respond($this->gateway()->requestAssertion($person, $binding, [self::CREDENTIAL]));

        self::assertSame(FailureReason::INVALID_CODE, $this->gateway()->verifyAssertion($person, $binding, [], $response));
        self::assertSame(FailureReason::INVALID_CODE, $this->gateway()->verifyAssertion($person, $binding, [self::OTHER_CREDENTIAL], $response));
    }

    /**
     * Rows of `[a response that is not one, by what it lacks]`.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideMalformedResponses(): iterable
    {
        yield 'no challenge' => [['credential' => []]];

        yield 'a blank challenge' => [['challenge' => '', 'credential' => []]];

        yield 'a challenge that is not text' => [['challenge' => 1, 'credential' => []]];

        yield 'no credential' => [['challenge' => 'challenge']];

        yield 'a credential that is neither an array nor text' => [['challenge' => 'challenge', 'credential' => 1]];
    }

    /**
     * A response without a usable challenge or credential never verifies, and
     * is not handed on.
     *
     * @param  array<string, mixed>  $response
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedResponses')]
    public function testAMalformedResponseNeverVerifies(array $response): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertSame(FailureReason::INVALID_CODE, $this->gateway()->verifyAssertion($person, $this->bindingOf($person, $session), [self::CREDENTIAL], $response));
    }

    /**
     * An assertion whose signature does not hold is an invalid code, as is one
     * whose sign counter went backwards.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionThatDoesNotHoldIsAnInvalidCode(): void
    {
        [$person, $session] = $this->passkeyFactor();

        $binding  = $this->bindingOf($person, $session);
        $response = $this->respond($this->gateway()->requestAssertion($person, $binding, [self::CREDENTIAL]));

        self::assertIsArray($response['credential']);
        self::assertIsArray($response['credential']['response']);

        $forged                                        = $response;
        $forged['credential']['response']['signature'] = VirtualAuthenticator::encode('forged signature');

        self::assertSame(FailureReason::INVALID_CODE, $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], $forged));

        self::assertInstanceOf(PasskeyAssertion::class, $this->assertAgain($person, $binding));

        $this->authenticator()->setCounter(self::CREDENTIAL, 0);

        self::assertSame(FailureReason::INVALID_CODE, $this->assertAgain($person, $binding));
    }

    /**
     * Rows of `[laravel-authentication's failure reason, MFA's]`.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 1: \SineMacula\Laravel\Mfa\Enums\FailureReason}>
     */
    public static function provideFailureReasons(): iterable
    {
        yield 'an expired challenge' => [AuthenticationFailureReason::PASSKEY_CHALLENGE_EXPIRED, FailureReason::EXPIRED];

        yield 'a challenge already answered' => [AuthenticationFailureReason::PASSKEY_CHALLENGE_USED, FailureReason::REPLAYED];

        yield 'an unknown challenge, or another binding\'s' => [AuthenticationFailureReason::PASSKEY_CHALLENGE_INVALID, FailureReason::EXPIRED];

        yield 'an assertion that does not hold' => [AuthenticationFailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CODE];

        yield 'a counter that went backwards' => [AuthenticationFailureReason::PASSKEY_COUNTER_REGRESSED, FailureReason::INVALID_CODE];

        yield 'no reason' => [null, FailureReason::INVALID_CODE];
    }

    /**
     * Each of `laravel-authentication`'s failure reasons crosses as MFA's.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $expected
     * @return void
     */
    #[DataProvider('provideFailureReasons')]
    public function testEachFailureReasonCrosses(?AuthenticationFailureReason $reason, FailureReason $expected): void
    {
        self::assertSame($expected, PasskeyGatewayAdapter::reason($reason));
    }

    /**
     * An application that names no `jwt` guard cannot be resolved, nor can any
     * while `laravel-authentication` is not the application's authentication,
     * and neither can an identity it does not sign in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUnresolvedReferencesThrow(): void
    {
        $person   = $this->createPerson();
        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        $owner   = IdentityReference::of($person);
        $binding = new ProofBinding($owner->type, $owner->key, 'not-a-guard', 'sign-in', Purpose::STEP_UP);

        self::assertSame(ReferenceKind::GUARD, self::unresolved(fn (): mixed => $this->gateway()->requestAssertion($person, $binding, [self::CREDENTIAL]))->kind);
        $response = ['challenge' => 'challenge', 'credential' => []];

        self::assertSame(ReferenceKind::GUARD, self::unresolved(fn (): mixed => $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], $response))->kind);
        self::assertSame(ReferenceKind::IDENTITY, self::unresolved(fn (): mixed => $this->gateway()->requestAssertion($stranger, $binding, [self::CREDENTIAL]))->kind);

        $this->app?->instance('auth', new IlluminateAuthManager($this->app));

        $signIn = new ProofBinding($owner->type, $owner->key, self::GUARD, 'sign-in', Purpose::STEP_UP);

        self::assertSame(ReferenceKind::GUARD, self::unresolved(fn (): mixed => $this->gateway()->requestAssertion($person, $signIn, [self::CREDENTIAL]))->kind);
    }

    /**
     * The gateway under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway
     */
    #[\Override]
    protected function passkeyGateway(): PasskeyGateway
    {
        return $this->gateway();
    }

    /**
     * A person holding a passkey factor, the same for every hook of a check.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function passkeyIdentity(): MultiFactorAuthenticatable
    {
        $this->arrangeForTheKit();

        self::assertNotNull($this->kitPerson);

        return $this->kitPerson;
    }

    /**
     * A step-up of the person's current sign-in.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function passkeyBinding(): ProofBinding
    {
        $this->arrangeForTheKit();

        self::assertNotNull($this->kitBinding);

        return $this->kitBinding;
    }

    /**
     * Arrange, once for every hook of a check, a person holding a passkey
     * factor and a step-up of their sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function arrangeForTheKit(): void
    {
        if ($this->kitPerson !== null) {
            return;
        }

        [$person, $session] = $this->passkeyFactor();

        $this->kitPerson  = $person;
        $this->kitBinding = $this->bindingOf($person, $session);
    }

    /**
     * A person signed in and acting on the session, holding a passkey factor
     * registered for an MFA enrolment, while MFA asks nothing of them, so the
     * session stays active.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Fixtures\Models\Person, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 2: \SineMacula\Laravel\Mfa\Models\Factor}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function passkeyFactor(): array
    {
        $this->requireNothing();

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->reauthenticate($person, $session);

        $enrolment    = new AuthenticationBinding($person, self::GUARD, $session->getSessionIdentifier(), AuthenticationPurpose::ENROLLMENT);
        $registration = $this->registerPasskey($person, self::CREDENTIAL, $enrolment);

        self::assertNotNull($registration->factor);

        return [$person, $session, Factor::query()->findOrFail($registration->factor->factor)];
    }

    /**
     * The response the virtual authenticator gives to the options handed out,
     * as the client hands it back.
     *
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     *
     * @throws \SodiumException
     */
    private function respond(array $options): array
    {
        $challenge = $options['challenge'];
        $request   = $options['options'];

        self::assertIsString($challenge);
        self::assertIsArray($request);

        /** @var array<string, mixed> $request */
        return ['challenge' => $challenge, 'credential' => $this->authenticator()->get($request, self::CREDENTIAL)];
    }

    /**
     * Request a new assertion of the passkey factor, answer it with the virtual
     * authenticator and verify the answer.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \Throwable
     */
    private function assertAgain(Person $person, ProofBinding $binding): FailureReason|PasskeyAssertion
    {
        $response = $this->respond($this->gateway()->requestAssertion($person, $binding, [self::CREDENTIAL]));

        return $this->gateway()->verifyAssertion($person, $binding, [self::CREDENTIAL], $response);
    }

    /**
     * A ceremony's binding to the person's session for the purpose.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function bindingOf(Person $person, EloquentSession&Model $session, Purpose $purpose = Purpose::STEP_UP): ProofBinding
    {
        $owner = IdentityReference::of($person);

        return new ProofBinding($owner->type, $owner->key, self::GUARD, $this->signInReference($session), $purpose);
    }

    /**
     * From now on, have MFA ask nothing of the identity, neither as the
     * application's requirement nor as its own, so a session judged again after
     * a factor change stays active.
     *
     * @return void
     */
    private function requireNothing(): void
    {
        config()->set('mfa.applications.' . self::GUARD . '.requirement', 'never');

        $this->app?->instance(IdentityRequirement::class, new class implements IdentityRequirement {
            /**
             * Ask nothing of the identity.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
            {
                return Requirement::none();
            }
        });
    }

    /**
     * Have the MFA application of each guard named offer the `passkey` type.
     *
     * @param  string  ...$guards
     * @return void
     */
    private static function offerPasskeysOn(string ...$guards): void
    {
        foreach ($guards as $guard) {
            config()->set('mfa.applications.' . $guard, ['types' => ['passkey'], 'requirement' => 'never']);
        }
    }

    /**
     * The gateway under test, resolved from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\PasskeyGatewayAdapter
     */
    private function gateway(): PasskeyGatewayAdapter
    {
        $gateway = $this->app?->make(PasskeyGatewayAdapter::class);

        self::assertInstanceOf(PasskeyGatewayAdapter::class, $gateway);

        return $gateway;
    }

    /**
     * Assert the call is refused by throwing MFA's refusal, and return it.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refusal(\Closure $call): OperationRefusedException
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            return $exception;
        }

        self::fail('The ceremony was not refused.');
    }

    /**
     * Assert the call throws an unresolved reference, and return it.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function unresolved(\Closure $call): UnresolvedReferenceException
    {
        try {
            $call();
        } catch (UnresolvedReferenceException $exception) {
            return $exception;
        }

        self::fail('The reference was resolved.');
    }
}
