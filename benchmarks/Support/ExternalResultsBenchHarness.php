<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Iam\Sso\ExternalResults;
use SineMacula\Laravel\Iam\Sso\Renewal;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Fixtures\Sso\Redemptions;

/**
 * External result benchmark fixtures: an admitted `sign_in` redemption with its
 * accepted evidence and captured provenance, an admitted `reauthenticate`
 * redemption, and the renewal it recorded, each built once.
 *
 * Building `laravel-authentication`'s external result is the one piece of the
 * redemptions this package computes itself, on every redemption, inside the
 * redemption's transaction and under SSO's locks: it validates every value
 * again as `laravel-authentication` builds it, and encodes the provenance as
 * the provider context, which is the costliest part.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalResultsBenchHarness
{
    /** @var \SineMacula\Laravel\Sso\Handoffs\RedemptionResult An admitted sign-in, with its evidence and provenance. */
    private RedemptionResult $signIn;

    /** @var \SineMacula\Laravel\Sso\Handoffs\RedemptionResult An admitted re-authentication. */
    private RedemptionResult $reauthentication;

    /** @var \SineMacula\Laravel\Iam\Sso\Renewal The renewal the re-authentication recorded. */
    private Renewal $renewal;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->signIn           = Redemptions::signIn();
        $this->reauthentication = Redemptions::reauthentication();
        $this->renewal          = new Renewal(Redemptions::identity(), Redemptions::SESSION, CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT), Redemptions::evidence());
    }

    /**
     * Build the sign-in's external result.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function buildsASignIn(): void
    {
        ExternalResults::from($this->signIn);
    }

    /**
     * Build the re-authentication's external result.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function buildsARenewal(): void
    {
        ExternalResults::renewing($this->reauthentication, $this->renewal);
    }
}
