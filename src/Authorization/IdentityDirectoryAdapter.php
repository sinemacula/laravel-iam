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
 * `laravel-authorization`'s identity directory, answered from
 * `laravel-authentication`'s principals (IAM-6.7, IAM-6.8, AUTHZ-14.2): the
 * principals an identity owns are those its `principals()` relation lists, as
 * `laravel-authentication` lists them for a sign-in.
 *
 * `laravel-authorization`'s own default knows an identity's principals only
 * under its own subject resolver, and calls every list incomplete under this
 * package's (`SubjectResolverAdapter`), so its grant scope query would never
 * answer `within` and SSO would link nobody by a verified domain (IAM-6.8), and
 * every grant would be classified as widening the identity's scope for want of
 * the list (IAM-6.7). Under this package the subjects are
 * `laravel-authentication`'s principals, each acting for its identity
 * (`Principal::getIdentity()`), so that identity's own list is the complete
 * answer:
 *
 * - an identity that owns principals (`HasPrincipals`) owns exactly those its
 *   `principals()` relation reads, on the write connection (`WriteConnection`),
 *   as `laravel-authentication` reads them, but without the principal model's
 *   global scopes, each named by its morph class and key, and the list is
 *   complete: a principal a global scope hides (one soft-deleted, say) still
 *   holds its grants, and is restored without a grant being written, so no
 *   grant hook would report the scope it widens, and is listed too. A relation
 *   that is no Eloquent query, whose scopes cannot be set aside, is not read,
 *   and the list is incomplete;
 * - an identity that is itself a principal (`Principal`), owning none, acts as
 *   itself alone, as `laravel-authentication` signs it in, and its list is
 *   complete and empty: the identity's own grants are the query's to read;
 * - an identity that is neither has its principals from a principal resolver
 *   the application binds to `laravel-authentication`, which no directory can
 *   list, so its list is incomplete and names none;
 * - an identity that cannot be resolved (a type the morph map does not name as
 *   an Eloquent identity of `laravel-authentication`'s, or no stored row of
 *   exactly that key, `IdentityReferences`) has an incomplete list, naming
 *   none, as the contract asks of a directory that cannot tell: the grant scope
 *   query then answers `unknown`, and the grant hook treats the grant as
 *   widening, never the other way.
 *
 * A read that fails throws, and is never taken for an empty list. It reads no
 * request, nor the current user, and keeps nothing between calls (IAM-8.1), so
 * it is transient.
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
     * The principals the identity owns, as its `principals()` relation lists
     * them, and whether the list is complete.
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

        $principals = WriteConnection::during($found, static fn (): array => WriteConnection::query($query)->get()->all());
        $references = [];

        foreach ($principals as $principal) {
            $references[] = Reference::of($principal);
        }

        return IdentityPrincipals::complete($references);
    }

    /**
     * The relation's query without the principal model's global scopes, or
     * `null` for a relation that is no Eloquent query, whose scopes cannot be
     * set aside.
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
