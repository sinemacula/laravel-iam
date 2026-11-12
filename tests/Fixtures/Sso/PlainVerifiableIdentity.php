<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Auth\GenericUser;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A verifiable identity that is no Eloquent model, so it has no table to
 * search.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainVerifiableIdentity extends GenericUser implements HasVerifiableIdentifiers, Identity
{
    /**
     * Every identifier is the one the identity was given.
     *
     * @param  string  $type
     * @return ?string
     */
    #[\Override]
    public function getIdentifierForVerification(string $type): ?string
    {
        $identifier = $this->attributes[$type] ?? null;

        return is_string($identifier) ? $identifier : null;
    }

    /**
     * Every identifier is verified.
     *
     * @param  string  $type
     * @return bool
     */
    #[\Override]
    public function hasVerifiedIdentifier(string $type): bool
    {
        return true;
    }

    /**
     * Record nothing.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function markIdentifierAsVerified(string $type, string $identifier): bool
    {
        return false;
    }
}
