<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Testing\Seams\ProvisionerContract;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The `Provisioner` contract kit (IAM-7.1): the provisioner always creates a
 * new identity, inserted by the call that answers it, never one whose
 * attributes the result matches, creates that identity's membership of the
 * result's tenant, and throws for a result it declines.
 *
 * A test case proves the application's provisioner by using this trait and
 * implementing the hooks against its own data: a result it provisions for, an
 * existing identity and a result carrying that identity's attributes (its email
 * address, say), a result it declines, and whether an identity is a member of a
 * tenant, read as the application reads its memberships. Insert each identity
 * with its model events on, as the listener requires. Each check delegates to
 * `ProvisionerContract`. Run it where the provisioner's writes reach a
 * database, as they do in the listener's transaction.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ProvisionerTests
{
    /**
     * Each identity the provisioner answers is a new one, inserted by the call
     * that answered it.
     *
     * @return void
     */
    public function testProvisionerCreatesANewIdentity(): void
    {
        $provisioner = $this->provisioner();
        $result      = $this->provisionedResult();

        ProvisionerContract::assertCreatesANewIdentity(static fn (): Identity => $provisioner->createIdentity($result));
    }

    /**
     * A result whose attributes match an existing identity's is provisioned a
     * new identity, never the existing one.
     *
     * @return void
     */
    public function testProvisionerNeverAnswersAnExistingIdentity(): void
    {
        $provisioner = $this->provisioner();
        $existing    = $this->existingIdentity();
        $result      = $this->resultMatching($existing);

        ProvisionerContract::assertNeverAnswersAnExistingIdentity(static fn (): Identity => $provisioner->createIdentity($result), $existing);
    }

    /**
     * The provisioner creates a new identity's membership of the result's
     * tenant.
     *
     * @return void
     */
    public function testProvisionerCreatesTheNewIdentitysMembership(): void
    {
        $provisioner = $this->provisioner();
        $result      = $this->provisionedResult();
        $identity    = $provisioner->createIdentity($result);

        ProvisionerContract::assertCreatesTheMembership(
            static fn () => $provisioner->createMembership($identity, $result->tenantId, $result),
            fn (): bool => $this->isMemberOf($identity, $result->tenantId),
        );
    }

    /**
     * A result the provisioner declines throws, rather than be answered an
     * identity.
     *
     * @return void
     */
    public function testProvisionerRefusesByThrowing(): void
    {
        $provisioner = $this->provisioner();
        $result      = $this->declinedResult();

        ProvisionerContract::assertRefusesByThrowing(static fn (): Identity => $provisioner->createIdentity($result));
    }

    /**
     * The provisioner under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\Provisioner
     */
    abstract protected function provisioner(): Provisioner;

    /**
     * A result the provisioner provisions for.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    abstract protected function provisionedResult(): VerifiedResult;

    /**
     * An identity that already exists, stored.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    abstract protected function existingIdentity(): Identity;

    /**
     * A result the provisioner provisions for, carrying the existing identity's
     * attributes: its email address, or whatever else the provisioner reads.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $existing
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    abstract protected function resultMatching(Identity $existing): VerifiedResult;

    /**
     * A result the provisioner declines.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    abstract protected function declinedResult(): VerifiedResult;

    /**
     * Whether the identity is a member of the tenant, as the application reads
     * its memberships.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return bool
     */
    abstract protected function isMemberOf(Identity $identity, string $tenantId): bool;
}
