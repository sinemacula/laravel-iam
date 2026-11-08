<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * A principal resolver for identities that hold memberships beside themselves:
 * a hint resolves to the membership of that id the identity holds, or to the
 * identity itself when it names the identity, and no hint to the identity
 * itself, its default principal.
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
     * The membership the hint names, when the identity holds it; the identity
     * itself with no hint, or a hint that names it; nothing otherwise.
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
