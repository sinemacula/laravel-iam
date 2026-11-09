<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * SSO's link storage, as the bound linker is it (IAM-4.9).
 *
 * SSO finds its link storage only as the bound `Contracts\Linker` that
 * implements `Contracts\LinkStorage`, and never binds `LinkStorage` itself. So
 * `LinkStorage` is answered from the bound linker on every call, never from a
 * store of its own: with this package's binding that is SSO's own
 * `Links\LinkStore`, and with an application's own linker it is that linker, so
 * whatever resolves `LinkStorage` writes and reads exactly the links SSO
 * resolves, and never past a linker the application put in front of the store
 * or bound to link nothing. A linker that is no link storage (SSO's
 * `Links\NoLinks` among them), or that is this storage itself, is a
 * `LogicException` before anything is read or written, as SSO refuses what
 * needs link storage then.
 *
 * It keeps nothing: the linker is resolved on each call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BoundLinkStorage implements LinkStorage
{
    /** @var string What is wrong with a bound linker that is no link storage of its own, naming its class and no value. */
    public const string NOT_STORAGE = '[%s] is answered by the bound [%s], but the [%s] bound is no link storage of its own: bind [%s] or a wrapper of it.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the bound linker on each call. */
        private Container $container,
    ) {}

    /**
     * What the result's connection, issuer and subject resolve to, for the
     * client, as the bound linker answers.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[\Override]
    public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
    {
        return self::storage($this->linker())->resolve($result, $client);
    }

    /**
     * The number of links the identity holds in the connection, as the bound
     * linker counts them.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[\Override]
    public function holdings(string $connectionId, IdentityReference $identity): int
    {
        return self::storage($this->linker())->holdings($connectionId, $identity);
    }

    /**
     * Make an active link of the subject through the bound linker.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S107")
     */
    #[\Override]
    public function create(
        SsoConnection $connection,
        LinkSubject $subject,
        IdentityReference $identity,
        LinkOrigin $origin,
        ClientContext $client,
        ?Caller $caller = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation {
        return self::storage($this->linker())->create($connection, $subject, $identity, $origin, $client, $caller, $application, $purpose, $reference);
    }

    /**
     * Confirm the link through the bound linker.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $locked
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[\Override]
    public function confirm(SsoConnection $locked, string $linkId, ClientContext $client, ?string $application = null, ?RequestReference $reference = null): void
    {
        self::storage($this->linker())->confirm($locked, $linkId, $client, $application, $reference);
    }

    /**
     * Suspend the locked link through the bound linker.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[\Override]
    public function suspend(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId, string $protocol, ClientContext $client): void
    {
        self::storage($this->linker())->suspend($linkId, $identity, $connectionId, $tenantId, $protocol, $client);
    }

    /**
     * Revoke the sessions established through the locked link, through the
     * bound linker.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[\Override]
    public function revokeSessions(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId): void
    {
        self::storage($this->linker())->revokeSessions($linkId, $identity, $connectionId, $tenantId);
    }

    /**
     * The one writer of a reserved row, as the bound linker answers it.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkReservations
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[\Override]
    public function reservations(): LinkReservations
    {
        return self::storage($this->linker())->reservations();
    }

    /**
     * The linker bound at this moment.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function linker(): Linker
    {
        return $this->container->make(Linker::class);
    }

    /**
     * The link storage the linker is, refusing a linker that is none, or that
     * is this storage itself and would answer from itself without end.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Linker  $linker
     * @return \SineMacula\Laravel\Sso\Contracts\LinkStorage
     *
     * @throws \LogicException
     */
    private static function storage(Linker $linker): LinkStorage
    {
        if (!$linker instanceof LinkStorage || $linker instanceof self) {
            throw new \LogicException(sprintf(self::NOT_STORAGE, LinkStorage::class, Linker::class, $linker::class, LinkStore::class));
        }

        return $linker;
    }
}
