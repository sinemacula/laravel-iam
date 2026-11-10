<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Records, as `laravel-authorization`'s last decision, an allow that read an
 * authentication requirement in a session or about an identity, and reads the
 * last decision back, so a test of an MFA adapter can show it forgets the
 * decision that depended on the authentication it changed (IAM-6.11).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RecordsRequirementDecisions
{
    /**
     * Record an allow that read an authentication requirement, made in the
     * session given, about the identity given, as the request's last decision.
     *
     * @param  ?string  $session
     * @param  ?\Illuminate\Database\Eloquent\Model  $identity
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function recordRequirementDecision(?string $session, ?Model $identity = null): Decision
    {
        $decision = Decision::allow(DecisionStage::ALLOW)->withFreshness(new RequirementFreshness($session));

        $this->lastDecisionStore()->put($decision, new DecisionProvenance(identity: $identity === null ? null : Reference::of($identity)), $session);

        return $decision;
    }

    /**
     * The request's last decision, whatever session reads it.
     *
     * @return ?\SineMacula\Laravel\Authorization\Evaluation\Decision
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function lastDecision(): ?Decision
    {
        return $this->lastDecisionStore()->get();
    }

    /**
     * The request's store of the last decision.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lastDecisionStore(): LastDecisionStore
    {
        $store = $this->app?->make(LastDecisionStore::class);

        self::assertInstanceOf(LastDecisionStore::class, $store);

        return $store;
    }
}
