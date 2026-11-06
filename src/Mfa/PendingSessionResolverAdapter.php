<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\PendingCredential;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * MFA's pending session resolver, read from `laravel-authentication`'s pending
 * session a pending credential names (IAM-3.3).
 *
 * `fromRequest()` is the edge, the one place a request is read: the credential
 * is taken by `laravel-authentication`'s own extractor
 * (`PendingCredential::extract()`), from the body field it reads one from (the
 * JSON body, or the form body of a request that may have one), never the query
 * string or a header. It is checked by `Auth::sessions()->pending()` on the
 * default guard, the guard MFA names its application after, which reads without
 * a lock and writes nothing. A request with no such field has no pending
 * session; one whose credential names no live pending session of the guard, or
 * that is not a credential at all, is refused by throwing, as is a default
 * guard that holds no sessions or a session whose identity is none of MFA's
 * (IAM-8.2), so the request is never served as the guard's user instead.
 *
 * `revalidate()`, which MFA asks under the identity's lock, reads no request:
 * it reads the session again from the credential the context it is handed keeps
 * (`PendingContext::credential()`), on the guard that context's application
 * names, never the default guard's. As MFA's contract has it, a session that no
 * longer stands is answered `null`, which MFA turns into a refusal of the
 * action: a context that kept no credential, a credential that names no live
 * pending session of the guard any more (expired, discarded or activated
 * meanwhile), and a session that is not the one the context names (another key,
 * or another identity). A guard that holds no sessions still throws, as a
 * misconfiguration (IAM-8.2).
 *
 * `fromCredential()` reads no request either: it reads the pending session a
 * credential handed in as a plain value names, on the guard the application
 * given names, and answers `null` when it names no live pending session there.
 * It serves this package's own adapters that are handed a pending credential
 * rather than a request (`PasskeyFactorGateAdapter`, for a passkey registered
 * on a pending sign-in).
 *
 * The pending session crosses as MFA's pending context: its identity, the guard
 * as the application, its key as the sign-in id, its first factor and further
 * proofs bound to that sign-in under the identity's current verification
 * generation, the requirement it still falls short of, MFA's pending actions
 * among those its first outstanding requirement allows, when its credential
 * expires, and the credential itself, hidden, so the context can be read again
 * and the pending completion can satisfy the session it names. The further
 * proofs are read newest first, up to the bound `laravel-authentication` sets
 * on one read, and handed over oldest first, as MFA keeps them; a proof that
 * would not survive translation is refused with the translator's exception
 * rather than left out.
 *
 * Stateless: the guard and the session are read on every call, so nothing
 * outlives the request (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingSessionResolverAdapter implements PendingSessionResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator  $changes
     */
    public function __construct(

        /** Resolves the default guard and its session service. */
        private CurrentSession $sessions,

        /** Translates the session's proofs. */
        private ProofTranslator $proofs,

        /** Translates the requirement the session falls short of. */
        private RequirementTranslator $requirements,

        /** Translates the actions the session allows. */
        private ChangeTranslator $changes,
    ) {}

    /**
     * The pending sign-in the request's credential names, or `null` when it
     * carries none.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function fromRequest(Request $request): ?PendingContext
    {
        $guard      = $this->sessions->defaultGuard();
        $credential = PendingCredential::extract($request);

        if ($credential === null) {
            return null;
        }

        if (!$credential instanceof Secret) {
            throw self::unresolved($guard);
        }

        $presented = $credential->reveal();
        $pending   = $this->sessions->sessions($guard)->pending($presented) ?? throw self::unresolved($guard);

        return $this->context($pending, $presented);
    }

    /**
     * The pending sign-in as it stands now, read again from the credential the
     * context keeps, or `null` when it no longer stands.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function revalidate(PendingContext $pending): ?PendingContext
    {
        $credential = $pending->credential();

        if ($credential === null) {
            return null;
        }

        $application = $pending->application;
        $now         = $this->sessions->sessions($application)->pending($credential);

        return $now === null || !self::isTheSession($now, $pending) ? null : $this->context($now, $credential);
    }

    /**
     * The pending sign-in the credential names on the application's guard, or
     * `null` when it names no live pending session there.
     *
     * @param  string  $application
     * @param  string  $credential
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function fromCredential(string $application, #[\SensitiveParameter] string $credential): ?PendingContext
    {
        $pending = $this->sessions->sessions($application)->pending($credential);

        return $pending === null ? null : $this->context($pending, $credential);
    }

    /**
     * Whether the pending session read again is the one the context names: the
     * same key, held by the same identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $now
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return bool
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function isTheSession(PendingSession $now, PendingContext $pending): bool
    {
        return SignIn::reference($now->session, $pending->application) === $pending->sessionId
            && IdentityReference::of($now->identity)->is(IdentityReference::of($pending->identity));
    }

    /**
     * MFA's pending context for `laravel-authentication`'s pending session,
     * keeping the credential that names it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  string  $credential
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function context(PendingSession $pending, #[\SensitiveParameter] string $credential): PendingContext
    {
        $identity = $pending->identity;

        if (!$identity instanceof MultiFactorAuthenticatable) {
            throw UnresolvedReferenceException::forMfaIdentity($identity::class);
        }

        $application = $pending->guard;
        $signIn      = new SignIn(IdentityReference::of($identity), $application, SignIn::reference($pending->session, $application), VerificationGeneration::current($identity));

        $counting = $pending->proofs(null, null, RequirementSubject::MAX_LIMIT);
        $further  = array_reverse(array_filter($counting, static fn (RecordedProof $proof): bool => $proof->kind !== ProofKind::FIRST_FACTOR));

        return new PendingContext(
            $identity,
            $application,
            $signIn->session,
            $this->proofs->toMfa($pending->firstFactor, $signIn),
            $this->requirements->toMfa($pending->requirement),
            $this->changes->pendingActions($pending->actions()),
            $pending->expiresAt,
            array_map(fn (RecordedProof $proof) => $this->proofs->toMfa($proof, $signIn), $further),
            $credential,
        );
    }

    /**
     * The refusal of a pending credential that names no live pending session of
     * the guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function unresolved(string $guard): UnresolvedReferenceException
    {
        $message = 'The request\'s pending credential names no live pending session of the guard [%s] that may still activate,'
            . ' so the request is refused rather than served as anyone.';

        return new UnresolvedReferenceException(sprintf($message, $guard), ReferenceKind::SESSION, $guard);
    }
}
