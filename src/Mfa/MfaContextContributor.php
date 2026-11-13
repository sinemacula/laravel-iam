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
 * The `mfa` authentication context namespace, filled by MFA's contributor from
 * the subject's session proofs.
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
     * The session's `mfa` keys, or the neutral context with no live session.
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
