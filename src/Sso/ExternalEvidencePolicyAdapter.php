<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;

/**
 * `laravel-authentication`'s external evidence policy: only evidence SSO
 * accepted counts, and MFA's combination policy judges what it meets.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalEvidencePolicyAdapter implements ExternalEvidencePolicy
{
    /** @var int The verification generation, which MFA's combination policy never judges. */
    private const int GENERATION = 0;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Sso\ConnectionTrust  $connections
     */
    public function __construct(

        /** Resolves MFA's combination policy and this request's admitted redemption on each call. */
        private Container $container,

        /** Translates the requirement into MFA's. */
        private RequirementTranslator $requirements,

        /** Names the subject's identity as SSO names the identity a redemption linked. */
        private IdentityReferences $identities,

        /** Whether the subject's tenant trusts its connection. */
        private ConnectionTrust $connections,
    ) {}

    /**
     * Whether SSO accepted the evidence here and MFA finds it credible.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function accepts(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        $identity = $this->identities->reference($subject->identity);
        $accepted = $this->container->make(AdmittedRedemptions::class)->acceptedEvidence($subject->connectionId, $identity);

        return $accepted !== null && self::isAccepted($evidence, $accepted, $subject) && $this->satisfies($evidence, $requirement, $subject);
    }

    /**
     * Whether the evidence meets the requirement, from a trusted connection.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        $tenant = $subject->tenant;

        return $this->satisfies($evidence, $requirement, $subject) && ($tenant === null || $this->trusts($tenant, $subject));
    }

    /**
     * Whether the evidence is exactly what SSO accepted.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $accepted
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    private static function isAccepted(ExternalEvidence $evidence, AcceptedEvidence $accepted, EvidenceSubject $subject): bool
    {
        return $evidence->methods === $accepted->methods()
            && $evidence->context === $accepted->rawContext()
            && $evidence->authenticatedAt->equalTo(self::judgedAt($accepted, $subject));
    }

    /**
     * The accepted time to the second, never after the subject's time.
     *
     * @param  \SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $accepted
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return \Carbon\CarbonImmutable
     */
    private static function judgedAt(AcceptedEvidence $accepted, EvidenceSubject $subject): CarbonImmutable
    {
        $at = $accepted->authenticatedAt->startOfSecond();

        return $at->greaterThan($subject->now) ? $subject->now->startOfSecond() : $at;
    }

    /**
     * Whether MFA's policy finds the evidence meets a non-empty requirement.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function satisfies(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        // Evidence accepted for an empty requirement would count for anything.
        if ($requirement->isEmpty()) {
            return false;
        }

        $policy = $this->container->make(CombinationPolicy::class);

        return $policy->evaluate($this->requirements->toMfa($requirement), self::firstFactor($evidence, $subject))->meetsRequirement();
    }

    /**
     * The `external_provider` first factor MFA records for the sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function firstFactor(ExternalEvidence $evidence, EvidenceSubject $subject): Proof
    {
        $identity = ProofOwner::of($subject->identity);

        return new Proof(
            ProofKind::FIRST_FACTOR,
            SignInMethodManager::EXTERNAL_METHOD,
            new Channel(ChannelKind::EXTERNAL_PROVIDER, $subject->connectionId),
            null,
            ObservedProperties::none(),
            $evidence->authenticatedAt,
            new ProofBinding($identity->type, $identity->key, $subject->application, SignIn::UNNAMED, Purpose::SIGN_IN),
            self::GENERATION,
        );
    }

    /**
     * Whether the tenant trusts the subject's connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function trusts(Tenant $tenant, EvidenceSubject $subject): bool
    {
        $tenantId = IdentifierCoercion::stringify($tenant->getTenantIdentifier());

        if ($tenantId === null || $tenantId === '') {
            throw UnresolvedReferenceException::forTenantIdentifier();
        }

        return $this->connections->trusts($tenantId, $subject->connectionId, $subject->application);
    }
}
