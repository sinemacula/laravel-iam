<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;

/**
 * The `sso` namespace of the authentication context, projected from the
 * provenance SSO captured when the session was established.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoContextContributor implements AuthenticationContextContributor
{
    /**
     * The session's `sso` keys, without their prefix.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, list<string>|string|null>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function contribute(ContributionSubject $subject): array
    {
        $stored = $subject->provenance()?->providerContext?->toArray();
        $prefix = strlen(AuthenticationContext::NAMESPACE) + 1;
        $keys   = [];

        foreach (AuthenticationContext::fromStored($stored) as $key => $value) {
            $keys[substr($key, $prefix)] = $value;
        }

        return $keys;
    }
}
