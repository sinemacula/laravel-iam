<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * An identity directory an application names in
 * `authorization.identity_directory` in place of this package's: one that knows
 * no identity's principals, under a class of the application's, so a test can
 * tell it from both this package's and `laravel-authorization`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NamedIdentityDirectory implements IdentityDirectory
{
    /**
     * An incomplete list naming no principal.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @return \SineMacula\Laravel\Authorization\Support\IdentityPrincipals
     *
     * @SuppressWarnings("php:S1172")
     */
    #[\Override]
    public function principalsOf(Reference $identity): IdentityPrincipals
    {
        return IdentityPrincipals::incomplete();
    }
}
