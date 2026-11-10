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
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;

/**
 * Begins the sign-in and records the proofs of MFA's
 * `InteractsWithMfa::actingAsVerified()` through `laravel-authentication`,
 * which alone writes a session's proofs under this package's proof store.
 *
 * `begin()` starts a session for the identity on the guard the application
 * names through `laravel-authentication`'s `start()`, from a password first
 * factor (the `password` method, a `password` channel and the `pwd` value), as
 * an application that checked a password itself starts one: the identity's
 * stored credentials are neither read nor touched. The session is started as of
 * the time MFA's helper makes its proofs at, with the clock held there while it
 * starts, so its first factor is the password proof MFA's helper would
 * otherwise record, made at that time, and the helper keeps it. It runs in this
 * package's cross-member transaction from the client `CallerSignIn` names; a
 * sign-in refused, or left pending on anything but a further factor (a choice
 * of principal, say), throws a `LogicException` naming the guard and the
 * reason, inside that transaction, so it leaves nothing behind. A session that
 * activates is acted on, as `actingOnSession()` acts on one, so the requests
 * the test then sends are served on it. One left pending on a further factor (a
 * person who already holds a confirmed factor, under an application that then
 * requires one at sign-in) is kept pending, and its pending credential kept
 * until the further proof completes it. Either way the session's id, as this
 * package's proof store names it, is returned.
 *
 * `record()` keeps the sign-in's own first factor: through the proof store for
 * an active session, and, for the pending session it began, when it is a
 * password. It records the helper's further proof as the level's evidence
 * (`LevelEvidence::matching()`), made with a confirmed factor of its type the
 * identity holds, or one enrolled for it when it holds none (`FixtureFactors`),
 * in place of the synthetic factor the helper names, which the store would
 * leave out, with the clock held at the proof's own time while it is recorded,
 * so `laravel-authentication` records it at that time and judges it then: the
 * session it began on its own is stepped up as `actingOnVerifiedSession()`
 * steps one up (`VerifiedSession::stepUp()`), and the pending one is completed
 * as `CallerSignIn` completes one (`CallerCompletion::satisfy()`), then acted
 * on; a completion that leaves it pending all the same throws a
 * `LogicException` naming the reason, and rolls back. A further proof that is
 * no level's evidence, or that is not bound to the pending session it began or
 * the identity's current sign-in, is refused with MFA's
 * `ProofRefusedException`.
 *
 * It keeps one thing between its calls: the pending credential of the sign-in
 * it began, until the further proof completes it, forgotten by the next
 * `begin()`. MFA's helper resolves it once for each sign-in it arranges, and it
 * is bound transient, so nothing reaches another sign-in or test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerifiedSignInRecorderAdapter implements VerifiedSignInRecorder
{
    /** @var string The method the session is started with, and MFA's helper names its first factor by. */
    private const string METHOD = 'password';

    /** @var string The `amr` value of the password first factor. */
    private const string AMR = 'pwd';

    /** @var string Why a sign-in that did not activate, nor wait on a further factor, is refused. */
    private const string NOT_SIGNED_IN = 'The identity was not signed in on guard [%s] for actingAsVerified(): [%s].';

    /** @var string Why a pending sign-in the further proof did not activate is refused. */
    private const string STILL_PENDING = 'The further proof did not activate the pending sign-in on guard [%s] for actingAsVerified(): [%s].';

    /** @var string Why a first factor other than the pending sign-in's own is refused. */
    private const string NOT_ITS_FIRST_FACTOR = 'Only the sign-in\'s own first factor, the password it was started with, is kept.';

    /** @var string Why a further proof of no level's evidence is refused. */
    private const string NO_EVIDENCE = 'Only the further proof of a level actingAsVerified() makes is recorded: an email code, an authenticator app,'
        . ' or a hardware-protected passkey.';

    /** @var string Why a proof bound to no sign-in this began nor the identity's current one is refused. */
    private const string UNBOUND = 'The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.';

    /** @var array<string, \SineMacula\Laravel\Authentication\Secrets\Secret> The pending credential of the sign-in begun, by its session id, until the further proof completes it. */
    private array $waiting = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $current
     * @param  \SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter  $store
     * @param  \SineMacula\Laravel\Iam\Testing\VerifiedSession  $verified
     * @param  \SineMacula\Laravel\Iam\Testing\CallerCompletion  $completion
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     */
    public function __construct(

        /** Finds the identity and the guard's session service. */
        private readonly CurrentSession $current,

        /** Keeps an active sign-in's own first factor and names the current sign-in. */
        private readonly ProofStoreAdapter $store,

        /** Steps an active session up with a further proof of a level's evidence. */
        private readonly VerifiedSession $verified,

        /** Completes a pending session with a further proof of a level's evidence. */
        private readonly CallerCompletion $completion,

        /** Runs each sign-in and completion in one transaction on the storage connection. */
        private readonly CrossMemberTransaction $transaction,
    ) {}

    /**
     * Start a session for the identity on the application's guard from a
     * password first factor, as of the time given, act on it once it is active,
     * and return its id.
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
     * Keep the sign-in's own first factor, or record the further proof with a
     * factor the identity holds, at the proof's own time.
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
     * @throws \Throwable
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $binding    = $proof->binding;
        $credential = IdentityReference::of($identity)->owns($binding) ? ($this->waiting[$binding->sessionId] ?? null) : null;

        if ($proof->kind === ProofKind::FIRST_FACTOR) {
            $credential === null ? $this->store->record($identity, $proof) : self::assertItsOwnFirstFactor($proof);

            return;
        }

        $evidence = LevelEvidence::matching($proof) ?? throw new ProofRefusedException(self::NO_EVIDENCE);
        $provedAt = $proof->provedAt;

        if ($credential !== null) {
            $this->complete($binding, $credential, $evidence, $provedAt);

            return;
        }

        $this->assertOnTheCurrentSignIn($identity, $binding);

        self::asOf($provedAt, fn () => $this->verified->stepUp($identity, $binding->application, $evidence, $provedAt));
    }

    /**
     * The id of the session the sign-in began: acted on once it is active, or
     * its pending credential kept while it waits first on a further factor;
     * any other sign-in is refused.
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
     * Complete the pending session the proof is bound to with a further proof
     * of the evidence, made at the time given, and act on it once it is active.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @param  \SineMacula\Laravel\Iam\Testing\LevelEvidence  $evidence
     * @param  \Carbon\CarbonImmutable  $provedAt
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    private function complete(ProofBinding $binding, #[\SensitiveParameter] Secret $credential, LevelEvidence $evidence, CarbonImmutable $provedAt): void
    {
        $application = $binding->application;

        self::asOf($provedAt, fn () => $this->transaction->run(function () use ($application, $credential, $evidence, $provedAt): void {

            $result = $this->completion->satisfy($application, $credential, $evidence, $provedAt, CallerSignIn::client());

            self::actOn($result->session->record ?? throw new \LogicException(sprintf(self::STILL_PENDING, $application, CallerSignIn::reason($result))), $application);
        }));

        unset($this->waiting[$binding->sessionId]);
    }

    /**
     * Refuse a first factor that is not the password the pending session was
     * started with.
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
     */
    private function assertOnTheCurrentSignIn(MultiFactorAuthenticatable $identity, ProofBinding $binding): void
    {
        if (!IdentityReference::of($identity)->owns($binding) || $this->store->currentSession($identity, $binding->application) !== $binding->sessionId) {
            throw new ProofRefusedException(self::UNBOUND);
        }
    }

    /**
     * Act on the session on the guard, as `actingOnSession()` does, so the
     * requests the test then sends are served on it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $application
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function actOn(EloquentSession&Model $session, string $application): void
    {
        (new class {
            use InteractsWithAuthenticationContext;
        })->actingOnSession($session, $application);
    }

    /**
     * Run the work with the clock held at the time given, and put the clock
     * back as it was, however the work returns.
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
