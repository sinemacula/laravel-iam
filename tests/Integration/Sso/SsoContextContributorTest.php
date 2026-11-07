<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext as Context;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SsoContextContributor;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\AcceptsTheProvidersContext;
use Tests\TestCase;

/**
 * Integration tests for the `sso` namespace of `laravel-authentication`'s
 * authentication context, against SSO's context acceptance scenarios: a session
 * a sign-in through SSO established contributes exactly SSO's twelve keys, each
 * the value SSO's projection gives its stored provenance, the instants in
 * `Provenance::INSTANT_FORMAT`, so `Auth::context()` builds; a fact the sign-in
 * did not state is held as `null`, never absent; any other session contributes
 * no key; a re-authentication leaves every key as it was; and a stored
 * provenance SSO cannot restore, or a provenance that cannot be read, fails the
 * build rather than contribute nothing.
 *
 * Each scenario that reads a stored session runs at the connection's own level
 * on every engine, then at READ COMMITTED and REPEATABLE READ on MySQL and
 * PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoContextContributor::class)]
final class SsoContextContributorTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The table `laravel-authentication` keeps each session's external provenance in. */
    private const string PROVENANCE = 'authentication_provenance';

    /** @var string The authentication context class the provider asserts. */
    private const string ACR = 'urn:example:acr:silver';

    /** @var \Tests\Fixtures\Models\Person The person who signs in. */
    private Person $person;

    /**
     * Arrange SSO and link the person to the provider's subject.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->person = $this->createPerson();

        $this->linkThroughFlow($this->person);
    }

    /**
     * A session a sign-in through SSO established contributes exactly SSO's
     * keys, each without its prefix and with the value SSO's projection gives
     * the stored provenance, its instants strings in SSO's instant format, so
     * the context builds and reads each back by its full name.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionThroughSsoContributesEverySsoKey(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);

        $session  = $this->signInThroughSso(static fn (FakeIdToken $token): FakeIdToken => $token->with('amr', ['pwd', 'mfa'])->with('acr', self::ACR));
        $expected = AuthenticationContext::fromStored($this->storedFormOf($session));
        $context  = $this->contextOn($session);

        self::assertCount(count(AuthenticationContext::KEYS), $expected);
        $keys = array_map(static fn (string $key): string => substr($key, 4), AuthenticationContext::KEYS);

        self::assertSame($keys, array_keys($context->toArray()[AuthenticationContext::NAMESPACE] ?? []));

        foreach ($expected as $key => $value) {
            self::assertTrue($context->has($key), $key);
            self::assertSame($value, $context->get($key), $key);
        }

        self::assertSame($this->connectionId, $context->get('sso.connection'));
        self::assertSame(self::TENANT, $context->get('sso.tenant'));
        self::assertSame('oidc', $context->get('sso.protocol'));

        $instant = $context->get('sso.provider_auth_time');

        self::assertIsString($instant);
        self::assertNotFalse(\DateTimeImmutable::createFromFormat('!' . Provenance::INSTANT_FORMAT, $instant));
        self::assertSame(['pwd', 'mfa'], $context->get('sso.provider_amr'));
        self::assertSame(self::ACR, $context->get('sso.provider_acr'));
    }

    /**
     * A fact the sign-in did not state is held with a `null` value, never left
     * out: SSO's default evidence policy accepts nothing, so the session's
     * provider methods are none and its raw context classes `null`, and an
     * OpenID provider states no session deadline, each still a key of the
     * namespace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactTheSignInDidNotStateIsHeldAsNull(): void
    {
        $context = $this->contextOn($this->signInThroughSso());

        foreach (['sso.provider_acr', 'sso.provider_authn_context_class_ref', 'sso.provider_session_deadline', 'sso.session_not_after'] as $key) {
            self::assertTrue($context->has($key), $key);
            self::assertNull($context->get($key, 'absent'), $key);
        }

        self::assertSame([], $context->get('sso.provider_amr'));
    }

    /**
     * A session no external provider established contributes no `sso` key: the
     * namespace holds nothing, and a key's default is answered.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnyOtherSessionContributesNoKey(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $context = $this->contextOn($this->signIn($this->createPerson())->record);

        self::assertSame([], $context->toArray()[AuthenticationContext::NAMESPACE] ?? []);

        foreach (AuthenticationContext::KEYS as $key) {
            self::assertFalse($context->has($key), $key);
            self::assertSame('absent', $context->get($key, 'absent'), $key);
        }
    }

    /**
     * A session an external provider established with no stored form
     * contributes no key: its provenance holds no provider context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalSessionWithNoStoredFormContributesNoKey(): void
    {
        $session = $this->signInThroughSso();

        DB::table(self::PROVENANCE)->where('session_id', self::keyOf($session))->update(['provider_context' => null]);

        $context = $this->contextOn($this->freshSession($session));

        self::assertSame([], $context->toArray()[AuthenticationContext::NAMESPACE] ?? []);
        self::assertFalse($context->has('sso.connection'));
    }

    /**
     * A re-authentication through SSO records no provider context, so every
     * `sso` key is the sign-in's, as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationLeavesEveryKeyAsItWas(): void
    {
        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);

        $session = $this->signInThroughSso();
        $before  = $this->contextOn($session)->toArray()[AuthenticationContext::NAMESPACE] ?? [];

        $this->travel(30)->seconds();

        $handoff = $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($session));
        $renewed = Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client());

        self::assertInstanceOf(AccessTokenResult::class, $renewed);
        self::assertTrue($renewed->isIssued());

        $after = $this->contextOn($this->freshSession($session))->toArray()[AuthenticationContext::NAMESPACE] ?? [];

        self::assertNotSame([], $before);
        self::assertSame($before, $after);
    }

    /**
     * A stored provenance this version of SSO did not write fails the build
     * with SSO's `UnexpectedValueException`, never as an empty contribution.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStoredFormSsoCannotRestoreFailsTheBuild(): void
    {
        $session = $this->signInThroughSso();

        $foreign = json_encode(['version' => 99, 'connection' => $this->connectionId]);

        DB::table(self::PROVENANCE)->where('session_id', self::keyOf($session))->update(['provider_context' => $foreign]);

        $this->actingOnSession($this->freshSession($session), self::GUARD);

        $this->expectException(\UnexpectedValueException::class);

        Auth::context();
    }

    /**
     * A database error reading the session's provenance fails the build too,
     * never read as no stored form.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADatabaseErrorFailsTheBuild(): void
    {
        $session = $this->signInThroughSso();

        $this->actingOnSession($session, self::GUARD);

        Schema::drop(self::PROVENANCE);

        $this->expectException(QueryException::class);

        Auth::context();
    }

    /**
     * Sign the person in through SSO, the provider's ID token tailored as
     * given, failing unless a session starts active, and return it.
     *
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInThroughSso(?\Closure $tailor = null): EloquentSession&Model
    {
        $handoff = $this->handoff(tailor: $tailor);
        $answer  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);

        return $answer->session->record ?? self::fail('The sign-in established no session.');
    }

    /**
     * The authentication context of a request served with the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Context\AuthenticationContext
     *
     * @throws \Throwable
     */
    private function contextOn(EloquentSession&Model $session): Context
    {
        $this->actingOnSession($session, self::GUARD);

        return Auth::context() ?? self::fail('No authentication context was built.');
    }

    /**
     * The session as it is stored now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function freshSession(EloquentSession&Model $session): EloquentSession&Model
    {
        $fresh = $session->fresh();

        return $fresh instanceof EloquentSession ? $fresh : self::fail('The session is gone.');
    }

    /**
     * The provider context `laravel-authentication` keeps with the session,
     * decoded: SSO's stored provenance.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return array<array-key, mixed>
     */
    private function storedFormOf(Model $session): array
    {
        $stored = DB::table(self::PROVENANCE)->where('session_id', self::keyOf($session))->value('provider_context');
        $form   = json_decode(is_string($stored) ? $stored : '', true, flags: JSON_THROW_ON_ERROR);

        return is_array($form) ? $form : self::fail('The session keeps no provider context.');
    }
}
