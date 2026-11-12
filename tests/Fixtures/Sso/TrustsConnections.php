<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A combination policy that counts a trusted connection's first factor as AAL2
 * multifactor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TrustsConnections implements CombinationPolicy
{
    /** @var list<list<\SineMacula\Laravel\Mfa\Proofs\Proof>> The proofs of each evaluation asked, in order. */
    public array $asked = [];

    /**
     * Constructor.
     *
     * @param  list<string>  $connections
     */
    public function __construct(

        /** The connections whose provider's sign-in is trusted. */
        private readonly array $connections,
    ) {}

    /**
     * As the default answers.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    #[\Override]
    public function accepts(Proof $firstFactor, Channel $factor): bool
    {
        return (new DefaultCombinationPolicy)->accepts($firstFactor, $factor);
    }

    /**
     * AAL2 multifactor for a trusted provider's newest proof, and the default's
     * answer otherwise.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $this->asked[] = array_values($proofs);

        $proof = $proofs === [] ? null : $proofs[array_key_last($proofs)];

        if ($proof === null || !$this->isTrusted($proof)) {
            return (new DefaultCombinationPolicy)->evaluate($requirement, ...$proofs);
        }

        $met   = [];
        $unmet = [];

        foreach ($requirement->parts() as $part) {

            $maxAge = $requirement->maxAge($part);
            $fresh  = $maxAge === null || $proof->provedAt->greaterThanOrEqualTo(CarbonImmutable::now()->subSeconds($maxAge));

            if ($part !== RequirementPart::PHISHING_RESISTANCE && $fresh) {
                $met[] = $part;

                continue;
            }

            $unmet[] = $part;
        }

        return new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['mfa'], $met, $unmet, multifactorAt: $proof->provedAt);
    }

    /**
     * Whether the proof is a trusted provider's first factor or
     * reauthentication.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return bool
     */
    private function isTrusted(Proof $proof): bool
    {
        $channel = $proof->channel;

        return in_array($proof->kind, [ProofKind::FIRST_FACTOR, ProofKind::FIRST_FACTOR_REAUTHENTICATION], true)
            && $channel?->kind === ChannelKind::EXTERNAL_PROVIDER
            && in_array($channel->reference(), $this->connections, true);
    }
}
