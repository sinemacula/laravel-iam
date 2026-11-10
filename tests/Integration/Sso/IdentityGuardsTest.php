<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\IdentityGuards;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\PlainIdentity;
use Tests\TestCase;

/**
 * Integration tests for taking SSO's identity guard of several identities at
 * once (IAM-6.7, IAM-7.5): every guard is taken in ascending order of SSO's
 * digest, whatever order the identities are given in, and they are answered in
 * that order, as a list; an identity that cannot be named to SSO is refused
 * before any guard is taken; and with no transaction open on the storage
 * connection nothing is locked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityGuards::class)]
final class IdentityGuardsTest extends TestCase
{
    use MigratesSso, SignsInPeople;

    /**
     * Identities given in descending order of SSO's digest have their guards
     * taken, and are answered, in ascending order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsAreTakenInAscendingOrderOfSsosDigest(): void
    {
        $people = [];

        for ($person = 0; $person < 4; $person++) {

            $created = $this->createPerson();

            $people[self::digestOf($created)] = $created;
        }

        krsort($people, SORT_STRING);

        $taken = $this->recordGuardsTaken();

        $answered = DB::transaction(fn (): array => $this->guards()->acquire(array_values($people)));

        $ascending = array_keys($people);

        sort($ascending, SORT_STRING);

        self::assertSame($ascending, $taken->getArrayCopy());
        self::assertSame($ascending, array_map(self::digestOf(...), $answered));
        self::assertSame(array_keys($answered), range(0, count($answered) - 1));
        self::assertSame(4, IdentityGuard::query()->count());
    }

    /**
     * An identity that is no Eloquent model cannot be named to SSO, and is
     * refused before any guard is taken, however late it is given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatCannotBeNamedIsRefusedBeforeAnyGuardIsTaken(): void
    {
        $person = $this->createPerson();

        try {
            DB::transaction(fn (): array => $this->guards()->acquire([$person, new PlainIdentity(['id' => 7])]));

            self::fail('An identity that cannot be named was taken a guard of.');
        } catch (UnresolvedReferenceException) {
            self::assertSame(0, IdentityGuard::query()->count());
        }
    }

    /**
     * With no transaction open on the storage connection, SSO refuses to take a
     * guard, and nothing is locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoGuardIsTakenOutsideATransaction(): void
    {
        $person = $this->createPerson();

        try {
            $this->guards()->acquire([$person]);

            self::fail('A guard was taken outside a transaction.');
        } catch (\LogicException) {
            self::assertSame(0, IdentityGuard::query()->count());
        }
    }

    /**
     * Record the digest of every identity whose guard is taken, in order.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordGuardsTaken(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $taken */
        $taken = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($taken): void {

            if (!str_contains($query->sql, 'sso_identity_guards') || !str_starts_with(strtolower(ltrim($query->sql)), 'insert')) {
                return;
            }

            foreach ($query->bindings as $binding) {
                if (!is_string($binding) || preg_match('/^[0-9a-f]{64}$/', $binding) !== 1) {
                    continue;
                }

                $taken->append($binding);
            }
        });

        return $taken;
    }

    /**
     * SSO's digest of the person.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     */
    private static function digestOf(Person $person): string
    {
        return IdentityLock::digest(self::referenceOf($person));
    }

    /**
     * The reference SSO names the person by.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function referenceOf(Person $person): IdentityReference
    {
        $key = $person->getKey();

        return new IdentityReference($person->getMorphClass(), is_int($key) || is_string($key) ? (string) $key : self::fail('The person has no key.'));
    }

    /**
     * The guards under test.
     *
     * @return \SineMacula\Laravel\Iam\Sso\IdentityGuards
     */
    private function guards(): IdentityGuards
    {
        return $this->app?->make(IdentityGuards::class) ?? self::fail('The application has not booted.');
    }
}
