<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;

/**
 * `laravel-authorization`'s requirement checker, answered by MFA's requirement
 * check on the proofs of the subject's own session (IAM-6.3, AUTHZ-8.3,
 * AUTHZ-14.1), so a policy statement's authentication requirement gets the same
 * answer as sign-in, a tenant's policy and step-up.
 *
 * `laravel-authorization` hands it the subject, carrying the session it signed
 * in with (`SubjectResolverAdapter`), and asks only about a subject with one; it
 * reads nothing of the request or the guard. The session is the subject's
 * guard's (its application), found by its key through the subject's identity's
 * own sessions, on the write connection (`CurrentSession::named()`), so another
 * identity's session is never judged. The subject must be accounted for by that
 * identity, as `laravel-authorization`'s contract asks: a principal must act
 * for it, and any other subject must be it (or name no identity, when it is its
 * own), so a subject paired with another identity's session is refused, and
 * the session must act in the subject's tenant, whether the tenant is
 * `laravel-authentication`'s or `laravel-authorization`'s own reference to it,
 * so one tenant's provider trust is never applied to a principal in another:
 * the proofs judged are always the subject's own. An identity MFA reads as
 * inactive (its bound `ActiveStateResolver`) meets no requirement, as MFA's
 * contract has it and its own route gate answers, so a session that stepped
 * up before its identity was suspended or deactivated meets nothing; its
 * proofs are not read. A subject with no guard, an
 * identity MFA cannot hold factors for, a guard that holds no sessions, a key
 * that names no session of the identity's, a tenant that cannot be read, and
 * an assurance level MFA does not know are each refused by throwing (IAM-8.2),
 * which `laravel-authorization` reads as undecidable, so an allow the
 * requirement guards does not apply and a deny it guards does. A subject with
 * no session never reaches it: `laravel-authorization` finds every part of
 * the requirement unmet without asking, so neither an allow nor a deny the
 * requirement guards applies; it is refused here too, should anything else
 * ask.
 *
 * The session's proofs are read through `laravel-authentication`'s public
 * readers (`Auth::sessions($guard)->firstFactor()` and `proofs()`), handed the
 * session itself, so a key a later sign-in reused is never read as it: the
 * first factor, and the further proofs a requirement can be met with since the
 * oldest time a part's maximum age allows (all of them when a part has none),
 * the newest `RequirementSubject::MAX_LIMIT` of them. These are the kinds the
 * authentication requirement check reads (`RequirementCheckAdapter`) and a
 * reauthentication at an external provider besides, which that check leaves out
 * only because `laravel-authentication` counts such a proof through its
 * external evidence policy first; `laravel-authorization` has no such policy,
 * so the session's reauthentication at its provider is read here as MFA's own
 * route gate reads it (`ProofStoreAdapter`). A pending, revoked or ended
 * session has none, so nothing but an empty requirement could be met. They are
 * translated as the proof store's are (`SignInProofs`), a provider's proof
 * naming its connection only under the evidence SSO accepted and the trust of
 * the session's tenant (`ProviderTrust::accepted()`), and MFA's check judges
 * each part on the newest proof meeting it within its maximum age, so a fresh
 * weak proof and a stale strong one never meet a requirement together. Outside
 * a transaction the proofs are read plainly; inside one on the session model's
 * connection the session's row is locked and they are read current, as
 * `laravel-authentication`'s readers choose.
 *
 * Its answer depends on the subject's session alone, never on the record a
 * check is about, so it is scope invariant, and a statement stating a
 * requirement compiles in `whereAuthorized()`. It holds nothing between calls
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementCheckerAdapter implements AuthenticationRequirementChecker, ScopeInvariant
{
    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> The kinds of proof read beside the first factor: every kind a requirement can be met with, a reauthentication at an external provider included. */
    private const array FURTHER_KINDS = [
        ProofKind::FIRST_FACTOR_REAUTHENTICATION,
        ProofKind::EXTERNAL_REAUTHENTICATION,
        ProofKind::ADDITIONAL_FACTOR,
        ProofKind::RECOVERY_CODE,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     * @param  \SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver  $active
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\SignInProofs  $proofs
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** MFA's requirement check, the one asked. */
        private RequirementCheck $check,

        /** MFA's active state of an identity: an inactive one meets nothing. */
        private ActiveStateResolver $active,

        /** Finds the subject's session, and the readers of its proofs. */
        private CurrentSession $sessions,

        /** Reads the session's proofs as MFA's proofs of the sign-in. */
        private SignInProofs $proofs,

        /** Translates the requirement into MFA's, and MFA's evaluation back. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * Judge the requirement on the proofs of the subject's session, unmet in
     * every part while MFA reads the subject's identity as inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        $application = $subject->guard   ?? throw UnresolvedReferenceException::forGuard('');
        $key         = $subject->session ?? throw UnresolvedReferenceException::forSession($application);
        $identity    = self::identityOf($subject, $application);
        $translated  = $this->requirements->toMfa($requirement);

        if (!$this->active->isActive($identity)) {
            return RequirementResult::unmet($requirement->names());
        }

        $session = self::inTenantOf($subject, $this->sessions->named($identity, $application, $key), $application);
        $reader  = $this->sessions->sessions($application);
        $since   = RequirementCheckAdapter::since($translated, CarbonImmutable::now());
        $further = $reader->proofs($session, $since, self::FURTHER_KINDS, RequirementSubject::MAX_LIMIT);

        $recorded = [...array_filter([$reader->firstFactor($session)]), ...array_reverse($further)];

        return $this->requirements->result($this->check->check($translated, ...$this->proofs->of($identity, $application, $session, $recorded)));
    }

    /**
     * The identity whose session the subject signed in with, once the subject
     * is accounted for by it: a principal must act for it, and any other
     * subject must be it, unless the subject names no identity, when it is its
     * own; refused when the subject is not, or MFA cannot hold factors for the
     * identity, so another identity's proofs never answer for the subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function identityOf(Subject $subject, string $application): MultiFactorAuthenticatable
    {
        $model    = $subject->subject;
        $acting   = $model instanceof Principal ? $model->getIdentity() : null;
        $identity = $subject->identity ?? $acting ?? $model;

        if (!$identity instanceof MultiFactorAuthenticatable) {
            throw UnresolvedReferenceException::forMfaIdentity($identity::class);
        }

        $own = $acting ?? ($model instanceof Authenticatable ? $model : null);

        return $own === $identity || ($own !== null && IdentityReference::of($own)->is(IdentityReference::of($identity)))
            ? $identity
            : throw UnresolvedReferenceException::forSignIn($application);
    }

    /**
     * The session, once it is found to act in the subject's tenant: a session
     * of another tenant, or none, never answers for a subject in a tenant, nor
     * one of a tenant for a subject in none, so one tenant's provider trust is
     * never applied to a principal in another.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function inTenantOf(Subject $subject, Session $session, string $application): Session
    {
        return self::tenantOf($subject, $application) === $session->getTenantId() ? $session : throw UnresolvedReferenceException::forSignIn($application);
    }

    /**
     * The identifier of the subject's tenant, as a session records it, or
     * `null` for none. A tenant of `laravel-authentication`'s names itself
     * (`getTenantIdentifier()`), as the subject resolver hands it over; any
     * other is read as `laravel-authorization` reads a tenant
     * (`TenantScope::extractTenantPair()`), its key, so its own `Reference`,
     * which `AuthorizationScope::subjectIn()` puts on the request's subject for
     * a listing in a scope (`permissionsFor()`), is judged as the check itself
     * is. A session records its tenant's key alone, never its type, so the key
     * is all that is compared. A tenant that names itself by no string or
     * integer, or that `laravel-authorization` cannot read, cannot be compared,
     * and is refused.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $application
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function tenantOf(Subject $subject, string $application): ?string
    {
        $tenant = $subject->tenant;

        if ($tenant === null) {
            return null;
        }

        if ($tenant instanceof Tenant) {
            $identifier = $tenant->getTenantIdentifier();

            return is_string($identifier) || is_int($identifier) ? (string) $identifier : throw UnresolvedReferenceException::forSignIn($application);
        }

        try {
            return TenantScope::extractTenantPair($tenant)[1];
        } catch (InvalidTenantException) {
            throw UnresolvedReferenceException::forSignIn($application);
        }
    }
}
