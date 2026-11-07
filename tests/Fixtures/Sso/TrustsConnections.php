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
 * A combination policy an application that trusts its providers might bind: it
 * answers as MFA's default does, except that a sign-in whose one proof is a
 * first factor through an external provider on a connection it trusts is
 * multifactor authentication at AAL2, never phishing-resistant, each part
 * judged within its maximum age of the proof. It keeps the proofs it was asked
 * to evaluate, so a test can tell what it was handed.
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
     * Multifactor authentication at AAL2 for a trusted provider's sign-in, each
     * part met within its maximum age, and the default's answer otherwise.
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

        $proof = count($proofs) === 1 ? array_values($proofs)[0] : null;

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
     * Whether the proof is a first factor through an external provider on a
     * trusted connection.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return bool
     */
    private function isTrusted(Proof $proof): bool
    {
        $channel = $proof->channel;

        return $proof->kind    === ProofKind::FIRST_FACTOR
            && $channel?->kind === ChannelKind::EXTERNAL_PROVIDER
            && in_array($channel->reference(), $this->connections, true);
    }
}
