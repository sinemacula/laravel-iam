<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;

/**
 * Reports to SSO's scope widening (`Linking\ScopeWidening::widened()`) that
 * people come to hold a principal in one tenant, or a platform principal
 * (`null`), first in the transaction that writes it (IAM-7.3).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ScopeWidenings
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Storage\StorageConnection  $storage
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     */
    public function __construct(

        /** Resolves SSO's scope widening on each call. */
        private Container $container,

        /** Names each identity as SSO names an identity. */
        private IdentityReferences $identities,

        /** The connections the change runs on. */
        private DatabaseManager $database,

        /** The storage connection's name. */
        private StorageConnection $storage,

        /** Runs the report in a savepoint of the caller's transaction. */
        private CrossMemberTransaction $transaction,
    ) {}

    /**
     * Report that the identities come to hold a principal in the tenant, in a
     * savepoint of the caller's transaction; answer how many links SSO
     * suspended.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Identity>  $identities
     * @param  ?string  $tenantId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return int
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function widen(array $identities, ?string $tenantId, ClientContext $client): int
    {
        $references = array_map($this->identities->reference(...), $identities);
        $widening   = $this->container->make(ScopeWidening::class);
        $sso        = ClientTranslator::toSso($client);

        if ($this->database->connection($this->storage->name())->transactionLevel() === 0) {
            return $widening->widened($references, $tenantId, $sso);
        }

        return $this->transaction->run(static fn (): int => $widening->widened($references, $tenantId, $sso));
    }
}
