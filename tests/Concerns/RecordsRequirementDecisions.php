<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Facades\Authorization;

/**
 * Leaves the request holding a decision through `laravel-authorization`'s
 * facade, by making a check, and reads the last decision back through it, so a
 * test of a change to an identity's authentication can show the change has the
 * request's decisions forgotten (IAM-6.11).
 *
 * The check is a guest's, which `laravel-authorization` refuses as
 * `subject_unresolved` without reading a table, so the test needs none of its
 * migrations: the decision forgotten is the request's whoever it was about.
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
     * Make a check, and answer the last decision it left the request holding.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    protected function recordDecision(): Decision
    {
        Authorization::forUser(null)->can('invoices:refund');

        return Authorization::lastDecision() ?? self::fail('The check left the request holding no decision.');
    }

    /**
     * The request's last decision.
     *
     * @return ?\SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    protected function lastDecision(): ?Decision
    {
        return Authorization::lastDecision();
    }
}
