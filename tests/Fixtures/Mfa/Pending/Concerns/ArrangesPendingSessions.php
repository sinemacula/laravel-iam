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
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Pending\CountsAdditionalFactors;
use Tests\Fixtures\Mfa\Pending\RequiresAdditionalVerification;
use Tests\Fixtures\Models\Person;

/**
 * Arranges pending sessions for the pending adapters' tests.
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
     * Bind the pending adapters, needing the given number of further factors.
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
     * Sign the person in pending and return the pending credential.
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
     * A request carrying the pending credential in its form body.
     *
     * @param  string  $credential
     * @return \Illuminate\Http\Request
     */
    protected static function requestCarrying(#[\SensitiveParameter] string $credential): Request
    {
        return Request::create(self::VERIFY_PATH, 'POST', [self::CREDENTIAL_FIELD => $credential]);
    }

    /**
     * The pending context a request carrying the credential resolves to.
     *
     * @param  string  $credential
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \Throwable
     */
    protected function pendingContextFor(#[\SensitiveParameter] string $credential): PendingContext
    {
        $pending = $this->pendingResolver()->fromRequest(self::requestCarrying($credential));

        self::assertNotNull($pending);

        return $pending;
    }

    /**
     * The pending context, keeping the credential given in place of its own.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  ?string  $credential
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    protected static function keeping(PendingContext $pending, #[\SensitiveParameter] ?string $credential): PendingContext
    {
        return new PendingContext(
            $pending->identity,
            $pending->application,
            $pending->sessionId,
            $pending->firstFactor,
            $pending->requirement,
            $pending->actions,
            $pending->expiresAt,
            $pending->proofs,
            $credential,
        );
    }

    /**
     * An additional factor's proof made now on the pending sign-in.
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
     * MFA's successful verification of the proof on the pending session.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    protected function verified(PendingContext $pending, Proof $proof): VerificationResult
    {
        $check = $this->app?->make(MfaRequirementCheck::class);

        self::assertInstanceOf(MfaRequirementCheck::class, $check);

        $evaluation = $check->check($pending->requirement, $pending->firstFactor, ...$pending->proofs, ...[$proof]);
        $refreshes  = $check->check(Requirement::none(), $pending->firstFactor, $proof)->multifactorAt?->equalTo($proof->provedAt) ?? false;

        return VerificationResult::verified($proof, $evaluation, ['otp'], 'totp', $refreshes);
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
