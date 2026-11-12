<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Freshness;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * Decorates the freshness policy, recording each read mode and asker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsReadModes implements FreshnessPolicy
{
    /** @var string The namespace every adapter of this package's is declared in. */
    private const string ADAPTERS = 'SineMacula\Laravel\Iam\\';

    /** @var list<bool> Whether each freshness judgement, in the order asked, was asked current. */
    public array $modes = [];

    /** @var list<string> The operation each freshness judgement, in the order asked, was asked for. */
    public array $operations = [];

    /** @var list<?class-string> The adapter of this package's nearest on the call stack of each freshness judgement, in the order asked, or `null` when none was on it. */
    public array $askers = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness  $policy
     */
    public function __construct(

        /** The policy every question is passed on to. */
        private readonly ConfiguredFreshness $policy,
    ) {}

    /**
     * As the policy answers.
     *
     * @param  string  $application
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function requirement(string $application, string $operation, ?FreshnessRequirement $requirement = null): ?FreshnessRequirement
    {
        return $this->policy->requirement($application, $operation, $requirement);
    }

    /**
     * Record the read mode, then answer as the policy does in it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function freshProof(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?RecordedProof {
        $this->record($operation, $current);

        return $this->policy->freshProof($session, $operation, $requirement, $excludingFactor, $current);
    }

    /**
     * Record the read mode, then answer as the policy does in it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    #[\Override]
    public function freshUntil(
        Session $session,
        string $operation,
        ?FreshnessRequirement $requirement = null,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?CarbonImmutable {
        $this->record($operation, $current);

        return $this->policy->freshUntil($session, $operation, $requirement, $excludingFactor, $current);
    }

    /**
     * Record a freshness judgement's read mode, operation and asking adapter.
     *
     * @param  string  $operation
     * @param  bool  $current
     * @return void
     */
    private function record(string $operation, bool $current): void
    {
        $this->modes[]      = $current;
        $this->operations[] = $operation;
        $this->askers[]     = self::asker();
    }

    /**
     * The nearest class of this package's on the call stack, or `null`.
     *
     * @return ?class-string
     */
    private static function asker(): ?string
    {
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {

            $class = $frame['class'] ?? null;

            if ($class !== null && str_starts_with($class, self::ADAPTERS)) {
                return $class;
            }
        }

        return null;
    }
}
