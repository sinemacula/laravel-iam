<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Provisioning\InsertionWitness;

/**
 * What every provisioner must guarantee, as assertions (IAM-7.1): each identity
 * it answers is a new one, the very Eloquent model instance that call inserted,
 * never one it found, however closely the result's attributes match an existing
 * identity's, nor one it inserted before and kept; it creates the new
 * identity's membership of the tenant; and a result it declines throws, rather
 * than answer an identity.
 *
 * SSO's grant proves only the authority to provision for a result, not that the
 * identity is new, so a provisioner that resolved an existing identity by an
 * email address or any other mapped attribute would let whoever controls a
 * connection's attributes take over that account. The listener refuses an
 * identity whose insertion it did not witness during the call
 * (`Provisioning\InsertionWitness`), as each check here does, and this kit
 * proves the rest. Each assertion takes the question as a closure, so a test
 * case asks it as the listener would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
abstract class ProvisionerContract
{
    /**
     * Asking twice creates two identities, each an Eloquent model inserted by
     * the call that answered it, neither the other.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $create
     * @return void
     */
    public static function assertCreatesANewIdentity(\Closure $create): void
    {
        $first  = self::created($create);
        $second = self::created($create);

        Assert::assertFalse(self::isSame($first, $second), 'The provisioner answered the identity it created before, rather than create a new one.');
    }

    /**
     * Asked for a result whose attributes match an existing identity's, the
     * provisioner creates a new identity, never answers the existing one.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $create
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $existing
     * @return void
     */
    public static function assertNeverAnswersAnExistingIdentity(\Closure $create, Identity $existing): void
    {
        $created = self::created($create);

        Assert::assertFalse(self::isSame($created, $existing), 'The provisioner answered an existing identity whose attributes the result matches, rather than create a new one.');
    }

    /**
     * Asked for the new identity's membership of the tenant, the provisioner
     * creates it: the identity is no member before, and is one after.
     *
     * @param  \Closure(): void  $member
     * @param  \Closure(): bool  $isMember
     * @return void
     */
    public static function assertCreatesTheMembership(\Closure $member, \Closure $isMember): void
    {
        Assert::assertFalse($isMember(), 'The new identity was a member of the tenant before the provisioner created its membership.');

        $member();

        Assert::assertTrue($isMember(), 'The provisioner did not create the new identity\'s membership of the tenant.');
    }

    /**
     * Asking for a result the provisioner declines throws.
     *
     * @param  \Closure(): mixed  $ask
     * @return void
     */
    public static function assertRefusesByThrowing(\Closure $ask): void
    {
        $thrown = null;

        try {
            $ask();
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        Assert::assertNotNull($thrown, 'The provisioner answered for a result it declines, rather than throw.');
    }

    /**
     * The identity the call answers, asserted to be an Eloquent model, the very
     * instance the call inserted.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $create
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function created(\Closure $create): Identity&Model
    {
        [$identity, $inserted] = InsertionWitness::witness($create);

        Assert::assertInstanceOf(Model::class, $identity, 'The provisioner answered an identity that is no Eloquent model, which SSO cannot name.');
        Assert::assertTrue($inserted, 'The provisioner answered an identity it did not insert during the call.');

        return $identity;
    }

    /**
     * Whether the identity names the same one as the model: the same Eloquent
     * model's morph class and key.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $model
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $other
     * @return bool
     */
    private static function isSame(Identity&Model $model, Identity $other): bool
    {
        return $other instanceof Model && $model->getMorphClass() === $other->getMorphClass() && $model->getKey() === $other->getKey();
    }
}
