<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Resolves a hint to the membership it names, or to the identity itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResolvesMemberships implements PrincipalResolver
{
    /**
     * Constructor.
     *
     * @param  list<\Tests\Fixtures\Testing\Membership>  $memberships
     */
    public function __construct(

        /** The memberships the identities hold. */
        private array $memberships,
    ) {}

    /**
     * The membership the hint names, else the identity when the hint allows.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        $hinted = IdentifierCoercion::stringify($hint);

        foreach ($this->memberships as $membership) {

            if ($hinted !== null && $membership->id === $hinted && $membership->getIdentity()->getAuthIdentifier() === $identity->getAuthIdentifier()) {
                return $membership;
            }
        }

        $itself = $identity instanceof Principal && ($hinted === null || $hinted === IdentifierCoercion::stringify($identity->getPrincipalIdentifier()));

        return $itself ? $identity : null;
    }
}
