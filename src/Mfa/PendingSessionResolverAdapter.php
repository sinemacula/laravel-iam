<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
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
 * session the request's pending credential names (IAM-3.3).
 *
 * The credential is read where `laravel-authentication` reads it: the body
 * field `authentication.session.pending_credential_field` names (the JSON body,
 * or the form body of a request that may have one), never the query string or a
 * header. It is checked by `Auth::sessions()->pending()` on the default guard,
 * the guard MFA names its application after, which reads without a lock and
 * writes nothing. A request with no such field has no pending session; one
 * whose credential names no live pending session of the guard, or that is not a
 * credential at all, is refused by throwing, as is a default guard that holds
 * no sessions or a session whose identity is none of MFA's (IAM-8.2), so the
 * request is never served as the guard's user instead.
 *
 * The pending session crosses as MFA's pending context: its identity, the guard
 * as the application, its key as the sign-in id, its first factor and further
 * proofs bound to that sign-in under the identity's current verification
 * generation, the requirement it still falls short of, MFA's pending actions
 * among those its first outstanding requirement allows, and when its credential
 * expires. The further proofs are read newest first, up to the bound
 * `laravel-authentication` sets on one read, and handed over oldest first, as
 * MFA keeps them; a proof that would not survive translation is refused with
 * the translator's exception rather than left out.
 *
 * Stateless: the guard, the configuration and the session are read on every
 * call, so nothing outlives the request (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingSessionResolverAdapter implements PendingSessionResolver
{
    /** @var string Configuration key of the body field `laravel-authentication` reads a pending credential from. */
    private const string FIELD_KEY = 'authentication.session.pending_credential_field';

    /** @var string Field `laravel-authentication` reads when its configuration names none. */
    private const string DEFAULT_FIELD = 'pending_credential';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator  $changes
     */
    public function __construct(

        /** Resolves the default guard and its session service. */
        private CurrentSession $sessions,

        /** The configuration the credential's field is declared in. */
        private Repository $config,

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
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function resolve(Request $request): ?PendingContext
    {
        $guard      = $this->sessions->defaultGuard();
        $credential = $this->credential($request, $guard);

        if ($credential === null) {
            return null;
        }

        $pending = $this->sessions->sessions($guard)->pending($credential) ?? throw self::unresolved($guard);

        return $this->context($pending);
    }

    /**
     * The pending credential the request carries in its body, or `null` when it
     * carries none; a value in the field that is not a credential at all is
     * refused, as one naming no pending session of the guard would be. The
     * pending completion reads the credential it satisfies here too.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function credential(Request $request, string $guard): ?string
    {
        $body  = self::body($request);
        $field = $this->field();

        if (!array_key_exists($field, $body)) {
            return null;
        }

        $credential = $body[$field];

        return is_string($credential) && $credential !== '' ? $credential : throw self::unresolved($guard);
    }

    /**
     * MFA's pending context for `laravel-authentication`'s pending session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function context(PendingSession $pending): PendingContext
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
        );
    }

    /**
     * The body field the pending credential is read from.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function field(): string
    {
        $field = $this->config->get(self::FIELD_KEY, self::DEFAULT_FIELD);

        if (!is_string($field) || $field === '') {
            throw new \InvalidArgumentException(sprintf('%s must name the body field a pending credential is read from.', self::FIELD_KEY));
        }

        return $field;
    }

    /**
     * The request's body fields, as `laravel-authentication` reads them: the
     * JSON body, or the form body of a request that may have one; never the
     * query string.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<array-key, mixed>
     */
    private static function body(Request $request): array
    {
        if ($request->isJson()) {
            return $request->json()->all();
        }

        return in_array($request->getRealMethod(), ['GET', 'HEAD'], true) ? [] : $request->request->all();
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
