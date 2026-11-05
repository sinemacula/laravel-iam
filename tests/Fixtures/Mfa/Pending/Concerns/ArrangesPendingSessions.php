<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Pending\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck as MfaRequirementCheck;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Pending\CountsAdditionalFactors;
use Tests\Fixtures\Mfa\Pending\RequiresAdditionalVerification;
use Tests\Fixtures\Models\Person;

/**
 * Arranges what the tests of the pending adapters share: the two adapters bound
 * over MFA's defaults, `laravel-authentication` asking every sign-in for an
 * additional verification its stand-in check meets after a number of further
 * factors, people signed in pending with a password, the request carrying a
 * pending credential, and further-factor proofs MFA verified for a pending
 * session.
 *
 * The requirement adapters are not bound: their stand-ins keep these tests to
 * the pending adapters alone. The tables come from `MigratesMembers`, the
 * people from `SignsInPeople`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ArrangesPendingSessions
{
    use MigratesMembers, SignsInPeople;

    /** @var string The path the requests carrying a pending credential are made to. */
    private const string VERIFY_PATH = '/mfa/verify';

    /** @var string The body field `laravel-authentication` reads a pending credential from by default. */
    private const string CREDENTIAL_FIELD = 'pending_credential';

    /** @var string The factor reference the further-factor proofs name by default. */
    private const string FACTOR = 'factor-1';

    /**
     * Bind the pending adapters over MFA's defaults, and the stand-ins that
     * leave a password sign-in pending until it holds the given number of
     * further factors.
     *
     * @param  int  $needed
     * @return void
     */
    protected function bindPendingSeams(int $needed = 1): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        $app->instance(AdditionalFactorPolicy::class, new RequiresAdditionalVerification);
        $app->instance(AuthenticationRequirementCheck::class, new CountsAdditionalFactors($needed));
        $app->bind(PendingSessionResolver::class, PendingSessionResolverAdapter::class);
        $app->bind(PendingCompletion::class, PendingCompletionAdapter::class);
    }

    /**
     * Sign the person in with their password, failing the test unless the
     * session waits pending, and return its pending credential.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     *
     * @throws \Throwable
     */
    protected function signInPending(Person $person): string
    {
        $result = $this->attemptSignIn($person);

        if (!$result->isPending() || $result->credential === null) {
            self::fail(sprintf('The person did not sign in pending: [%s].', $result->reason->value ?? $result->status->value));
        }

        return $result->credential->reveal();
    }

    /**
     * A request carrying the pending credential in its form body, bound as the
     * request being served.
     *
     * @param  string  $credential
     * @return \Illuminate\Http\Request
     */
    protected function requestCarrying(#[\SensitiveParameter] string $credential): Request
    {
        $request = Request::create(self::VERIFY_PATH, 'POST', [self::CREDENTIAL_FIELD => $credential]);

        $this->app?->instance('request', $request);

        return $request;
    }

    /**
     * The pending context the pending credential resolves to, served on a
     * request carrying it.
     *
     * @param  string  $credential
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \Throwable
     */
    protected function pendingContextFor(#[\SensitiveParameter] string $credential): PendingContext
    {
        $pending = $this->pendingResolver()->resolve($this->requestCarrying($credential));

        self::assertNotNull($pending);

        return $pending;
    }

    /**
     * An additional factor's proof made now, as MFA makes one on the pending
     * session, for the purpose and on the sign-in given (the pending session's
     * own by default).
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  ?string  $session
     * @param  string  $factor
     * @param  ?\Carbon\CarbonImmutable  $provedAt
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    protected function factorProof(
        PendingContext $pending,
        Purpose $purpose = Purpose::SIGN_IN,
        ?string $session = null,
        string $factor = self::FACTOR,
        ?CarbonImmutable $provedAt = null,
    ): Proof {
        $owner = $pending->firstFactor->binding;

        return new Proof(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP, $factor),
            $factor,
            ObservedProperties::none(),
            $provedAt ?? CarbonImmutable::now(),
            new ProofBinding($owner->identityType, $owner->identityKey, $owner->application, $session ?? $owner->sessionId, $purpose),
            $pending->firstFactor->generation,
        );
    }

    /**
     * MFA's successful verification of the proof on the pending session,
     * evaluated by MFA's own requirement check with the session's first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    protected function verified(PendingContext $pending, Proof $proof): VerificationResult
    {
        $check = $this->app?->make(MfaRequirementCheck::class);

        self::assertInstanceOf(MfaRequirementCheck::class, $check);

        return VerificationResult::verified($proof, $check->check($pending->requirement, $pending->firstFactor, ...$pending->proofs, ...[$proof]), ['otp'], 'totp');
    }

    /**
     * The pending session resolver adapter, resolved from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter
     */
    protected function pendingResolver(): PendingSessionResolverAdapter
    {
        $resolver = $this->app?->make(PendingSessionResolverAdapter::class);

        self::assertInstanceOf(PendingSessionResolverAdapter::class, $resolver);

        return $resolver;
    }

    /**
     * The pending completion adapter, resolved from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter
     */
    protected function pendingCompleter(): PendingCompletionAdapter
    {
        $completion = $this->app?->make(PendingCompletionAdapter::class);

        self::assertInstanceOf(PendingCompletionAdapter::class, $completion);

        return $completion;
    }
}
