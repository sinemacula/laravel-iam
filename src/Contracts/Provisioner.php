<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The application's provisioner (IAM-7.1): what a person who signs in through
 * an SSO connection for the first time is made into, just in time, inside the
 * flow. The package decides when and in which transaction; what a provisioned
 * identity and its membership are is the application's own.
 *
 * It is asked only by this package's one listener of SSO's
 * `Events\ResultUnlinked` (`Provisioning\ProvisionOnUnlinkedResult`), only
 * while `iam.provisioning.provisioner` names it or it is bound in the
 * container, and only for a `sign_in` result that resolved to no identity and
 * holds no reservation. Both methods run inside the listener's one transaction
 * on the storage connection, in this order: `createIdentity()`, SSO's scope
 * widening for the new identity, `createMembership()`, then SSO's provisioning
 * helper, which writes the link. A refusal from the helper, or anything either
 * method throws, rolls all three back together; once the transaction commits,
 * the identity, its membership and the link stay made, even if the completion
 * then fails. Write every row on the storage connection: a write through
 * another connection is not atomic with the link and survives a rollback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface Provisioner
{
    /**
     * Create a new identity for the result, and answer it, stored.
     *
     * Always a new identity, inserted now: never one found by the result's
     * email address, subject or any other mapped attribute, which whoever
     * controls the connection's attributes could otherwise use to take over an
     * existing account (attaching a subject to an existing identity goes
     * through SSO's `link` purpose or a verified domain). It must be an
     * Eloquent model the listener can name to SSO, its morph class and key,
     * and the very instance this call inserted, with its model events on: the
     * listener witnesses the `created` event of every model inserted while
     * this runs (`Provisioning\InsertionWitness`), so an instance inserted
     * before the call and kept, a fresh instance of the row, or one inserted
     * quietly (`createQuietly()`, `saveQuietly()`, `withoutEvents()`) is
     * refused with a `LogicException` and rolled back. A model that declares
     * a `created` event of its own (`$dispatchesEvents`) is witnessed through
     * it, so that event keeps the model it is built with in a property, as
     * Eloquent builds it; one that keeps no model, while a listener of it
     * answers a value (which skips Eloquent's own `created` event), hides the
     * insertion and is refused the same way. Inserting a new row
     * needs no guard; take no lock on rows other writers share. Throw to
     * refuse: the completion then ends as a server error, with nothing written.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Throwable
     */
    public function createIdentity(#[\SensitiveParameter] VerifiedResult $result): Identity;

    /**
     * Create the new identity's membership of the tenant, the tenant that owns
     * the connection the result came through.
     *
     * It is called once SSO's scope widening holds the new identity's guard,
     * and before the link is written, so take no lock on rows other writers
     * share (a tenant-wide row, say): SSO takes the enforcing tenant's rule,
     * the connection and the links next, and a shared guard taken before them
     * inverts its lock order. A guard of the new identity's own rows is safe,
     * since no other transaction can name the identity before this one commits.
     * Whether the membership counts as accepted by the person is the
     * application's to record. Throw to refuse: the completion then ends as a
     * server error, with nothing written.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \Throwable
     */
    public function createMembership(Identity $identity, string $tenantId, #[\SensitiveParameter] VerifiedResult $result): void;
}
