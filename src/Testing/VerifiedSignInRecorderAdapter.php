<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;

/**
 * Begins MFA's `actingAsVerified()` sign-in and records its proofs through
 * `laravel-authentication`, which alone writes a session's proofs here.
 *
 * Bound transient, so the pending credential it holds never reaches another
 * sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerifiedSignInRecorderAdapter implements VerifiedSignInRecorder
{
    /** @var string The method the session starts with and MFA names its first factor by. */
    private const string METHOD = 'password';

    /** @var string The `amr` value of the password first factor. */
    private const string AMR = 'pwd';

    /** @var string Why a sign-in neither active nor waiting on a further factor is refused. */
    private const string NOT_SIGNED_IN = 'The identity was not signed in on guard [%s] for actingAsVerified(): [%s].';

    /** @var string Why a sign-in the further proof did not activate is refused. */
    private const string STILL_PENDING = 'The further proof did not activate the pending sign-in on guard [%s] for actingAsVerified(): [%s].';

    /** @var string Why a first factor other than the sign-in's own is refused. */
    private const string NOT_ITS_FIRST_FACTOR = 'Only the sign-in\'s own first factor, the password it was started with, is kept.';

    /** @var string Why a proof bound to no current sign-in is refused. */
    private const string UNBOUND = 'The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.';

    /** @var array<string, \SineMacula\Laravel\Authentication\Secrets\Secret> The pending credentials of begun sign-ins, by session id. */
    private array $waiting = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $current
     * @param  \SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter  $store
     * @param  \SineMacula\Laravel\Iam\Testing\FixtureFactors  $factors
     * @param  \SineMacula\Laravel\Iam\Testing\VerifiedSession  $verified
     * @param  \SineMacula\Laravel\Iam\Testing\CallerCompletion  $completion
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     */
    public function __construct(

        /** Finds the identity and the guard's session service. */
        private readonly CurrentSession $current,

        /** Keeps an active sign-in's first factor and names the current sign-in. */
        private readonly ProofStoreAdapter $store,

        /** The real factor the further proof names. */
        private readonly FixtureFactors $factors,

        /** Steps an active session up with the further proof. */
        private readonly VerifiedSession $verified,

        /** Completes a pending session with the further proof. */
        private readonly CallerCompletion $completion,

        /** Runs each sign-in and completion on the storage connection. */
        private readonly CrossMemberTransaction $transaction,
    ) {}

    /**
     * Start a password session as of the time given and return its id.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, CarbonImmutable $at): string
    {
        $this->waiting = [];

        $factor  = new FirstFactor($this->current->identity($identity), new Channel(ChannelKind::PASSWORD), methods: [self::AMR]);
        $context = new SignInContext(CallerSignIn::client());

        return self::asOf($at, fn (): string => $this->transaction->run(
            fn (): string => $this->begun($this->current->sessions($application)->start($factor, null, self::METHOD, $context), $application),
        ));
    }

    /**
     * Keep the first factor, or record the further proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $binding    = $proof->binding;
        $credential = ProofOwner::of($identity)->owns($binding) ? ($this->waiting[$binding->sessionId] ?? null) : null;

        if ($proof->kind === ProofKind::FIRST_FACTOR) {
            $credential === null ? $this->store->record($identity, $proof) : self::assertItsOwnFirstFactor($proof);

            return;
        }

        if ($credential !== null) {
            $this->complete($binding, $credential, $proof);

            return;
        }

        $this->assertOnTheCurrentSignIn($identity, $binding);

        $stepUp = new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, Purpose::STEP_UP);

        self::asOf($proof->provedAt, fn () => $this->verified->stepUp($identity, new Proof(
            $proof->kind,
            $proof->method,
            $proof->channel,
            $proof->reference,
            $proof->properties,
            $proof->provedAt,
            $stepUp,
            $proof->generation,
        )));
    }

    /**
     * The identity's confirmed factor for the level, enrolled when missing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \Throwable
     */
    #[\Override]
    public function factorReference(MultiFactorAuthenticatable $identity, string $application, AssuranceLevel $level): string
    {
        return $this->factors->held($identity, $application, $level);
    }

    /**
     * The begun session's id, acting on it or keeping its pending credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  string  $application
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function begun(SignInResult $result, string $application): string
    {
        $session = $result->session?->record;

        if ($session !== null) {
            self::actOn($session, $application);

            return SignIn::reference($session, $application);
        }

        $pending    = $result->pending;
        $credential = $result->credential;

        if ($pending?->requires[0] !== PendingRequirement::MFA || $credential === null) {
            throw new \LogicException(sprintf(self::NOT_SIGNED_IN, $application, CallerSignIn::reason($result)));
        }

        $signIn = SignIn::reference($pending->session, $application);

        $this->waiting[$signIn] = $credential;

        return $signIn;
    }

    /**
     * Complete the pending session at the proof's time and act on it.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    private function complete(ProofBinding $binding, #[\SensitiveParameter] Secret $credential, Proof $proof): void
    {
        $application = $binding->application;

        self::asOf($proof->provedAt, fn () => $this->transaction->run(function () use ($application, $credential, $proof): void {

            $result = $this->completion->satisfy($this->completion->pending($application, $credential), $proof, CallerSignIn::client());

            self::actOn($result->session->record ?? throw new \LogicException(sprintf(self::STILL_PENDING, $application, CallerSignIn::reason($result))), $application);
        }));

        unset($this->waiting[$binding->sessionId]);
    }

    /**
     * Refuse a first factor other than the pending session's password.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    private static function assertItsOwnFirstFactor(Proof $proof): void
    {
        if ($proof->method !== self::METHOD || $proof->channel?->kind !== MfaChannelKind::PASSWORD) {
            throw new ProofRefusedException(self::NOT_ITS_FIRST_FACTOR);
        }
    }

    /**
     * Refuse a proof that is not bound to its identity's current sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function assertOnTheCurrentSignIn(MultiFactorAuthenticatable $identity, ProofBinding $binding): void
    {
        if (!ProofOwner::of($identity)->owns($binding) || $this->store->currentSession($identity, $binding->application) !== $binding->sessionId) {
            throw new ProofRefusedException(self::UNBOUND);
        }
    }

    /**
     * Act on the session on the guard, as `actingOnSession()` does.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $application
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function actOn(EloquentSession&Model $session, string $application): void
    {
        (new class {
            use InteractsWithAuthenticationContext;
        })->actingOnSession($session, $application);
    }

    /**
     * Run the work with the clock held at the time given, then put it back.
     *
     * @template T
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @param  \Closure(): T  $work
     * @return T
     *
     * @param-immediately-invoked-callable $work
     */
    private static function asOf(CarbonImmutable $at, \Closure $work): mixed
    {
        $held = CarbonImmutable::getTestNow();

        CarbonImmutable::setTestNow($at);

        try {
            return $work();
        } finally {
            CarbonImmutable::setTestNow($held);
        }
    }
}
