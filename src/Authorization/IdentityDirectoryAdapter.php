<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Lists an identity's principals for `laravel-authorization` from its
 * `principals()` relation, incomplete when that cannot be read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityDirectoryAdapter implements IdentityDirectory
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Resolves the identity the reference names through the morph map. */
        private IdentityReferences $identities,
    ) {}

    /**
     * The principals the identity owns, and whether the list is complete.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @return \SineMacula\Laravel\Authorization\Support\IdentityPrincipals
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function principalsOf(Reference $identity): IdentityPrincipals
    {
        try {
            $found = $this->identities->identity(new IdentityReference($identity->type, $identity->id));
        } catch (\InvalidArgumentException|UnresolvedReferenceException) {
            return IdentityPrincipals::incomplete();
        }

        $query = $found instanceof HasPrincipals ? self::unscoped($found->principals()) : null;

        if ($query === null) {
            return !$found instanceof HasPrincipals && $found instanceof Principal ? IdentityPrincipals::complete() : IdentityPrincipals::incomplete();
        }

        // A soft-deleted or otherwise scoped-out principal keeps its grants.
        $principals = WriteConnection::during($found, static fn (): array => WriteConnection::query($query)->get()->all());
        $references = [];

        foreach ($principals as $principal) {
            $references[] = Reference::of($principal);
        }

        return IdentityPrincipals::complete($references);
    }

    /**
     * The relation's query without global scopes, or `null` if not Eloquent.
     *
     * @param  \Illuminate\Contracts\Database\Eloquent\Builder  $principals
     * @return ?\Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    private static function unscoped(Builder $principals): ?EloquentBuilder
    {
        $query = $principals instanceof Relation ? $principals->getQuery() : $principals;

        return $query instanceof EloquentBuilder ? $query->withoutGlobalScopes() : null;
    }
}
