<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor as MfaContributor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The `mfa` namespace of `laravel-authentication`'s authentication context,
 * filled by MFA's own contributor from the contribution subject and its proofs
 * (IAM-3.12, MFA-10.11, AUTH-11.8).
 *
 * The subject names everything MFA's `contributeFor()` is handed: the identity
 * the guard bound, the application (the context's, the guard's name), the
 * session as MFA names its sign-in (`SignIn::reference()`), and the session's
 * proofs, read through the subject's own public readers
 * (`ContributionSubject::proofs()` and `firstFactor()`), which read the
 * subject's session and never the request's. So the namespace is the same for a
 * context built for the request, for another session, or in a queued job:
 * nothing here reads the request, the guard's state or `Auth::user()`.
 *
 * MFA's obligations on its caller are kept here (MFA-10.11). The proofs come
 * from `laravel-authentication`'s record of the session, the newest
 * `RequirementSubject::MAX_LIMIT` of them, oldest first, with the session's
 * first factor ahead of them when it is older than all of them, since MFA
 * reports no evidence without exactly one; they are translated as the proof
 * store's are (`SignInProofs`). A session that is pending, revoked, ended or of
 * another guard has no proofs through those readers, and gets the neutral
 * context without MFA being asked; so does a subject with no session, and an
 * identity that cannot hold factors. MFA itself gives a machine and an inactive
 * identity the neutral context.
 *
 * The proofs are read as of the call: plainly outside a transaction, and
 * current, under the session row's lock, inside one on the session model's
 * connection, as `laravel-authentication`'s readers choose. Nothing makes them
 * agree with the package's own keys (`amr`, `mfa`), worked out before the
 * contributors run.
 *
 * It is registered under `mfa` (`MfaContributor::NAMESPACE`) in this package's
 * service provider's `boot()`, while the MFA capability's switch is on, and
 * resolved from the container serving each build. It keeps nothing between
 * builds (IAM-8.1), and an exception reading the proofs, or MFA's, propagates,
 * since a policy cannot be judged on part of a context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MfaContextContributor implements AuthenticationContextContributor
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor  $contributor
     * @param  \SineMacula\Laravel\Iam\Mfa\SignInProofs  $proofs
     */
    public function __construct(

        /** MFA's own contributor, which works the keys out. */
        private MfaContributor $contributor,

        /** Reads the session's proofs as MFA's proofs of the sign-in. */
        private SignInProofs $proofs,
    ) {}

    /**
     * The session's `mfa` keys, without their prefix: the neutral context for
     * an identity that cannot hold factors, and for a subject with no live,
     * active session.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    #[\Override]
    public function contribute(ContributionSubject $subject): array
    {
        $identity = $subject->identity;
        $session  = $subject->session;

        if (!$identity instanceof MultiFactorAuthenticatable || $session === null) {
            return MfaContributor::neutral();
        }

        $recorded = array_reverse($subject->proofs(limit: RequirementSubject::MAX_LIMIT));

        if ($recorded === []) {
            return MfaContributor::neutral();
        }

        if (!SignInProofs::holdsAFirstFactor($recorded)) {
            $recorded = [...array_filter([$subject->firstFactor()]), ...$recorded];
        }

        $application = $subject->context->application;

        return $this->contributor->contributeFor(
            $identity,
            $application,
            SignIn::reference($session, $application),
            ...$this->proofs->of($identity, $application, $session, $recorded),
        );
    }
}
