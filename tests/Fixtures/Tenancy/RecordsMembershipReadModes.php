<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;

/**
 * Memberships that record whether each read was pinned to the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsMembershipReadModes implements Memberships
{
    /** @var list<bool> Whether each question was asked pinned to the writer, in order. */
    public array $pinned = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\Memberships  $memberships
     */
    public function __construct(

        /** The memberships that answer. */
        private readonly Memberships $memberships,
    ) {}

    /**
     * Record the read mode, then answer.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Iam\Tenancy\MembershipSet
     *
     * @throws \Throwable
     */
    #[\Override]
    public function of(Identity $identity): MembershipSet
    {
        $this->pinned[] = $identity instanceof Model && self::readsOnWriter($identity->getConnection());

        return $this->memberships->of($identity);
    }

    /**
     * Whether the connection reads from its writer now.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function readsOnWriter(Connection $connection): bool
    {
        $read = \Closure::bind(static fn (Connection $bound): bool => $bound->readOnWriteConnection, null, Connection::class);

        return $read($connection);
    }
}
