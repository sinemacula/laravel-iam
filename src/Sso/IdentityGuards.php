<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Linking\IdentityLock;

/**
 * Takes SSO's identity guard of several identities at once, in SSO's order, for
 * a change that reports more than one of them to SSO's scope widening in one
 * transaction (IAM-6.7, IAM-7.5).
 *
 * SSO's lock order is the identity guard, then the connections, then the links,
 * and a transaction that changes several identities takes their guards in
 * ascending order of SSO's digest of each (`Linking\IdentityLock`). SSO's scope
 * widening (`Linking\ScopeWidening::widened()`) reports one identity: it takes
 * that identity's guard, then locks the connections of its links. Called for
 * one identity after another, the second guard would be taken after the first
 * identity's connections, and a grant, a reservation or an activation of the
 * second identity, which holds its guard and waits for one of those
 * connections, would deadlock with the change. So every guard is taken here
 * first, in that order, before any widening runs; each widening then takes its
 * identity's guard again, which, held already by the same transaction, waits
 * for nothing.
 *
 * SSO offers no widening of several identities, nor a public way to take the
 * guard, so this reaches SSO's own lock (`IdentityLock::acquire()`, which SSO
 * marks internal), resolved on each call, and SSO's digest
 * (`IdentityLock::digest()`) to order them. It runs inside the caller's
 * transaction on the storage connection, which holds each guard to its end;
 * with none open there it is SSO's `LogicException`, with nothing locked. Each
 * identity is named to SSO by its morph class and key
 * (`IdentityReferences::reference()`), one that is no Eloquent model throwing
 * `UnresolvedReferenceException` (IAM-8.2) before any guard is taken. It keeps
 * nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityGuards
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Resolves SSO's identity lock on each call. */
        private Container $container,

        /** Names each identity as SSO names an identity. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Take the guard of every identity given, in ascending order of SSO's
     * digest, inside the caller's transaction on the storage connection;
     * answer the identities in that order.
     *
     * @template TIdentity of \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @param  list<TIdentity>  $identities
     * @return list<TIdentity>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     */
    public function acquire(array $identities): array
    {
        $ordered = [];

        foreach ($identities as $identity) {

            $reference = $this->identities->reference($identity);

            $ordered[IdentityLock::digest($reference)] = [$reference, $identity];
        }

        ksort($ordered, SORT_STRING);

        $lock = $this->container->make(IdentityLock::class);

        foreach ($ordered as [$reference]) {
            $lock->acquire($reference);
        }

        return array_values(array_map(static fn (array $entry) => $entry[1], $ordered));
    }
}
