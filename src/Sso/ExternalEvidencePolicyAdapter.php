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
 * `laravel-authentication`'s external evidence policy, answered from the
 * evidence SSO accepted, with MFA's combination policy as the second gate
 * (IAM-4.6, IAM-5.1, SSO-8.7, AUTH-3.6, AUTH-3.12).
 *
 * There are two gates, and neither is the other. The first is SSO's: its
 * evidence contract decides, at redemption, which of the provider's own
 * assertions (`amr`, `acr` or `AuthnContextClassRef`) count at all, per
 * connection and within a maximum age, and its default accepts nothing.
 * `laravel-authentication` is handed only what it accepted (`ExternalResults`).
 * The second is MFA's: its combination policy decides what that evidence
 * satisfies, judging it as the first factor MFA records for an SSO sign-in, a
 * `first_factor` proof on an `external_provider` channel naming the connection,
 * alone. MFA's default policy classifies nothing an external provider reports,
 * so by default a provider's `mfa` never becomes multifactor authentication,
 * nor an additional verification, a level or phishing resistance, and nothing
 * is accepted or recorded; an application that trusts a provider rebinds MFA's
 * combination policy to trust that connection. The provider's methods
 * themselves never reach MFA: its proof carries none, so a rebound policy
 * trusts a provider by its connection, never by its `amr`. Everywhere else a
 * session's recorded first factor reaches MFA, the proof translator names the
 * connection only under the same two gates and the same tenant trust
 * (`Mfa\Translation\ProviderTrust`), so a policy that trusts the connection
 * never counts, by another path, what this policy would refuse.
 *
 * `accepts()` is asked inside the sign-in or re-authentication this package
 * redeems, and counts the evidence only as the evidence SSO's evidence contract
 * accepted in the redemption admitted in this request through the subject's
 * connection, for the identity that redemption linked
 * (`AdmittedRedemptions::acceptedEvidence()`), with exactly its methods and raw
 * context, and its time as `laravel-authentication` judges it at the subject's
 * time: the time SSO accepted, to the whole second, unless that is after the
 * subject's time, when it is the subject's time, to the whole second, as
 * `laravel-authentication` dates evidence its clocks disagree with. Evidence
 * handed to `laravel-authentication` by any other path, for another identity,
 * of another time, or after the redemption is over, is not SSO's, and is never
 * accepted. It is then credible for the requirement when MFA's combination
 * policy says the first factor meets it.
 *
 * `meets()` is asked for the identity level and for a tenant, with accepted
 * evidence only, at sign-in and on every later judgement of the session: the
 * evidence meets the whole requirement when MFA's combination policy says the
 * first factor, made at the evidence's time, meets every part within its
 * maximum age (MFA judges the ages against the current time, which is never
 * earlier than the subject's, so it is never more lenient). For a tenant, the
 * connection must be one the tenant trusts as well: one of its own (SSO's
 * connection records its tenant), or one its enforcement on the application
 * names (`Contracts\Enforcement::policy()`, as an inheriting tenant's rule
 * names the enforcing tenant's connections); one tenant's trust in a connection
 * is never another's (`ConnectionTrust`). That is read only once MFA's policy
 * has answered met, on the write connection, without a lock.
 *
 * A requirement that asks for nothing is never met: `laravel-authentication`
 * never asks with one, and evidence accepted for nothing would count for
 * anything. An identity whose key cannot be named throws (IAM-8.2). Both reads
 * take no lock and write nothing, so asking under the session's row lock
 * inverts nothing. Everything is resolved on each call, and nothing is kept
 * between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalEvidencePolicyAdapter implements ExternalEvidencePolicy
{
    /** @var int The verification generation the first factor is stamped with: MFA's combination policy never judges one, which its requirement check alone does. */
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
     * Whether the evidence is what SSO accepted in the redemption admitted in
     * this request, and MFA's combination policy finds it credible for the
     * requirement.
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
     * Whether the accepted evidence meets the whole requirement for the
     * subject, as MFA's combination policy judges it, from a connection the
     * subject's tenant, if any, trusts.
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
     * Whether the evidence is exactly what SSO's evidence contract accepted:
     * its methods, in order, its raw context, and its time as
     * `laravel-authentication` judges it at the subject's time.
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
     * The time SSO accepted the evidence for, as `laravel-authentication`
     * judges evidence at the subject's time: to the whole second, and dated at
     * the subject's time, to the whole second, when it is after that time.
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
     * Whether the tenant trusts the subject's connection: it is the tenant's
     * own, or the tenant's enforcement on the application names it.
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
