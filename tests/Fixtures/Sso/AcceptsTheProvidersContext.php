<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * An evidence contract that accepts whatever the provider's own assertion
 * stated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AcceptsTheProvidersContext implements EvidencePolicy
{
    /**
     * Accept the result's own authentication context as evidence.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     */
    #[\Override]
    public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): AcceptedEvidence
    {
        unset($connection);

        $context = $result->authenticationContext;

        return new AcceptedEvidence($result->connectionId, $context->authenticatedAt ?? $now, $context->methods, $context->contextClass);
    }
}
