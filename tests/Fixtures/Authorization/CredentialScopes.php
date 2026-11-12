<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * An application's own session policy source that caps no subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CredentialScopes implements SessionPolicySource
{
    /**
     * No cap, for any subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        return null;
    }
}
