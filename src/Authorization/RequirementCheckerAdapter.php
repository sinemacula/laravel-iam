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
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Judges `laravel-authorization`'s authentication requirements with MFA's
 * requirement check, on the proofs of the subject's own session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementCheckerAdapter implements AuthenticationRequirementChecker, ScopeInvariant
{
    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> The kinds of proof read beside the first factor, external reauthentication included. */
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
     * Judge the requirement on the subject's session; inactive meets nothing.
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
     * The identity the subject is or acts for.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
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

        return $own === $identity || ($own !== null && ProofOwner::of($own)->is(ProofOwner::of($identity)))
            ? $identity
            : throw UnresolvedReferenceException::forSignIn($application);
    }

    /**
     * The session, refused unless it acts in the subject's tenant.
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
     * The subject's tenant key as a session records it, or `null` for none.
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

        // A session records only its tenant's key, never the type.
        try {
            return TenantScope::extractTenantPair($tenant)[1];
        } catch (InvalidTenantException) {
            throw UnresolvedReferenceException::forSignIn($application);
        }
    }
}
