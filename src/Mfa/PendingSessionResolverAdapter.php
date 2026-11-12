<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\PendingCredential;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * MFA's pending session resolver, read from `laravel-authentication`'s pending
 * session a pending credential names on the default guard (IAM-3.3).
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

        /** Resolves the guard's session service. */
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
        $guard      = Auth::getDefaultDriver();
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
     * Whether the pending session read again is the one the context names.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $now
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return bool
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function isTheSession(PendingSession $now, PendingContext $pending): bool
    {
        return SignIn::reference($now->session, $pending->application) === $pending->sessionId
            && ProofOwner::of($now->identity)->is(ProofOwner::of($pending->identity));
    }

    /**
     * MFA's pending context for the pending session, keeping its credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  string  $credential
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function context(PendingSession $pending, #[\SensitiveParameter] string $credential): PendingContext
    {
        $identity = $pending->identity;

        if (!$identity instanceof MultiFactorAuthenticatable) {
            throw UnresolvedReferenceException::forMfaIdentity($identity::class);
        }

        $application = $pending->guard;
        $signIn      = new SignIn(ProofOwner::of($identity), $application, SignIn::reference($pending->session, $application), VerificationGeneration::current($identity));

        $trust   = ProviderTrust::accepted($pending->session->getTenantId());
        $further = [];

        foreach ($pending->proofs(null, null, RequirementSubject::MAX_LIMIT) as $proof) {

            if ($proof->kind === ProofKind::FIRST_FACTOR) {
                continue;
            }

            $further[] = $proof;
        }

        return new PendingContext(
            $identity,
            $application,
            $signIn->session,
            $this->proofs->toMfa($pending->firstFactor, $signIn, $trust),
            $this->requirements->toMfa($pending->requirement),
            $this->changes->pendingActions($pending->actions()),
            $pending->expiresAt,
            array_map(fn (RecordedProof $proof) => $this->proofs->toMfa($proof, $signIn, $trust), array_reverse($further)),
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
