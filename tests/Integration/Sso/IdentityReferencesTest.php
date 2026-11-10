<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\ColumnDefinition;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\HandledIdentity;
use Tests\Fixtures\Sso\PlainIdentity;
use Tests\Fixtures\Sso\UuidIdentity;
use Tests\TestCase;

/**
 * Integration tests for translating the identities SSO names by reference to
 * `laravel-authentication`'s identities and back: through the application's
 * morph map, or by class name without it, read by key on the write connection,
 * and only when the identity found is named by exactly that reference; anything
 * else throws (IAM-8.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityReferences::class)]
final class IdentityReferencesTest extends TestCase
{
    use MigratesMembers, SignsInPeople, SignsInThroughLinks;

    /** @var string The alias the morph map names people by, where a test maps them. */
    private const string ALIAS = 'person';

    /** @var string The handle the string-keyed identity is stored under. */
    private const string HANDLE = 'alice';

    /**
     * Create the tables of the identities keyed by a string and by a UUID, each
     * key compared as the engine's collation or type compares it, and on SQLite
     * case-insensitively.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $collation = Schema::getConnection()->getDriverName() === 'sqlite' ? 'NOCASE' : null;

        $keys = [
            HandledIdentity::TABLE => static fn (Blueprint $table): ColumnDefinition => $table->string('id'),
            UuidIdentity::TABLE    => static fn (Blueprint $table): ColumnDefinition => $table->uuid('id'),
        ];

        foreach ($keys as $name => $key) {

            Schema::dropIfExists($name);
            Schema::create($name, static function (Blueprint $table) use ($key, $collation): void {

                // @phpstan-ignore argument.type (a null collation leaves the engine's own, as every engine but SQLite keeps)
                $key($table)->primary()->collation($collation);

                $table->timestamps();
            });
        }
    }

    /**
     * Drop the keyed identities' tables, and forget any morph map a test set,
     * so the next test starts without one.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(HandledIdentity::TABLE);
        Schema::dropIfExists(UuidIdentity::TABLE);

        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * Without a morph map, a person is named by its class and its key, and the
     * reference resolves back to that very person, read once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonIsNamedByItsClassWithoutAMorphMap(): void
    {
        $person    = $this->createPerson();
        $reference = $this->references()->reference($person);

        self::assertSame(Person::class, $reference->type);
        self::assertSame(self::keyOf($person), $reference->id);

        DB::enableQueryLog();

        $identity = $this->references()->identity($reference);

        self::assertInstanceOf(Person::class, $identity);
        self::assertTrue($person->is($identity));
        self::assertCount(1, DB::getQueryLog());
    }

    /**
     * With a morph map, a person is named by its alias, and the alias resolves
     * back to that very person.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonIsNamedByItsAliasThroughTheMorphMap(): void
    {
        Relation::morphMap([self::ALIAS => Person::class]);

        $person    = $this->createPerson();
        $reference = $this->references()->reference($person);

        self::assertSame(self::ALIAS, $reference->type);
        self::assertTrue($person->is($this->references()->identity($reference)));
    }

    /**
     * With a morph map naming people by an alias, a reference naming a person
     * by its class is another reference, and resolves to nobody: it never
     * stands in for the alias `laravel-authentication` records sessions by.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAClassNameIsNotTheAliasTheMorphMapNames(): void
    {
        Relation::morphMap([self::ALIAS => Person::class]);

        $person = $this->createPerson();

        $this->assertUnresolved(new IdentityReference(Person::class, self::keyOf($person)));
    }

    /**
     * Rows of `[type]`: a type naming no class, one naming a class that is no
     * Eloquent model though it is an identity, and one naming an Eloquent model
     * that is no identity.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTypesOfNoIdentity(): iterable
    {
        yield 'no class' => ['App\Models\Nobody'];

        yield 'no Eloquent model' => [PlainIdentity::class];

        yield 'no identity' => [Session::class];
    }

    /**
     * A type naming no Eloquent identity resolves to nobody, and nothing is
     * queried.
     *
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideTypesOfNoIdentity')]
    public function testATypeNamingNoEloquentIdentityResolvesToNobody(string $type): void
    {
        DB::enableQueryLog();

        $this->assertUnresolved(new IdentityReference($type, '1'));

        self::assertSame([], DB::getQueryLog());
    }

    /**
     * A type names an identity only when it names, through the morph map or as
     * a class name, an Eloquent model that is an identity: a type naming no
     * class, a class that is no Eloquent model, and a model that is no identity
     * name none.
     *
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideTypesOfNoIdentity')]
    public function testATypeNamingNoEloquentIdentityNamesNoIdentity(string $type): void
    {
        self::assertFalse($this->references()->namesIdentity($type));
    }

    /**
     * A person's class names an identity, and so does its alias through the
     * morph map.
     *
     * @return void
     */
    public function testAPersonsClassAndAliasNameAnIdentity(): void
    {
        self::assertTrue($this->references()->namesIdentity(Person::class));
        self::assertFalse($this->references()->namesIdentity(self::ALIAS));

        Relation::morphMap([self::ALIAS => Person::class]);

        self::assertTrue($this->references()->namesIdentity(self::ALIAS));
    }

    /**
     * An id no stored person holds resolves to nobody.
     *
     * @return void
     */
    public function testAnIdNoPersonHoldsResolvesToNobody(): void
    {
        $this->createPerson();

        $this->assertUnresolved(new IdentityReference(Person::class, '987654'));
    }

    /**
     * An id that cannot be a person's key resolves to nobody without a query,
     * so no database error stands in for an unknown identity.
     *
     * @return void
     */
    public function testAnIdThatCannotBeAKeyIsNotQueried(): void
    {
        DB::enableQueryLog();

        $this->assertUnresolved(new IdentityReference(Person::class, 'not-a-key'));

        self::assertSame([], DB::getQueryLog());
    }

    /**
     * An identity keyed by a string or by a UUID resolves from the reference it
     * is named by, its key byte for byte.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStringOrUuidKeyedIdentityResolvesFromItsOwnReference(): void
    {
        foreach ([$this->createHandled(), $this->createUuid()] as $identity) {

            $reference = $this->references()->reference($identity);

            self::assertSame(self::keyOf($identity), $reference->id);
            self::assertTrue($identity->is($this->references()->identity($reference)));
        }
    }

    /**
     * Rows of `[id]` naming the stored handle `alice` not byte for byte: in
     * another case, which a case-insensitive collation matches, and with a
     * trailing space, which a pad-space collation matches.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideHandlesNotByteForByte(): iterable
    {
        yield 'another case' => [Str::upper(self::HANDLE)];

        yield 'a trailing space' => [self::HANDLE . ' '];
    }

    /**
     * A reference whose id the database matches to a stored string key that is
     * not its own byte for byte resolves to nobody: SSO keys its records by
     * those bytes, so it names another identity, and is never resolved to this
     * one.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideHandlesNotByteForByte')]
    public function testAStringKeyIsNotResolvedFromAnIdItIsNotByteForByte(string $id): void
    {
        $this->createHandled();

        $this->assertUnresolved(new IdentityReference(HandledIdentity::class, $id));
    }

    /**
     * A reference naming a stored UUID key in upper case, which a `uuid` type
     * or a case-insensitive collation matches, resolves to nobody.
     *
     * @return void
     */
    public function testAUuidKeyIsNotResolvedFromItsUpperCase(): void
    {
        $identity = $this->createUuid();

        self::assertNotSame(Str::upper(self::keyOf($identity)), self::keyOf($identity));

        $this->assertUnresolved(new IdentityReference(UuidIdentity::class, Str::upper(self::keyOf($identity))));
    }

    /**
     * A key held as a string is named as it is.
     *
     * @return void
     */
    public function testAStringKeyIsNamedAsItIs(): void
    {
        $person = (new Person)->setIncrementing(false)->setKeyType('string');

        $person->setAttribute($person->getKeyName(), 'p-1');

        self::assertSame('p-1', $this->references()->reference($person)->id);
    }

    /**
     * Rows of `[identity]`: an identity that is no Eloquent model, one with no
     * key yet, and one whose key is empty.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity}>
     */
    public static function provideUnnameableIdentities(): iterable
    {
        yield 'no Eloquent model' => [static fn (): PlainIdentity => new PlainIdentity(['id' => 1])];

        yield 'no key yet' => [static fn (): Person => new Person];

        yield 'an empty key' => [static function (): Person {

            $person = (new Person)->setIncrementing(false)->setKeyType('string');

            $person->setAttribute($person->getKeyName(), '');

            return $person;
        }];
    }

    /**
     * An identity SSO could not name by a reference that resolves back throws.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     */
    #[DataProvider('provideUnnameableIdentities')]
    public function testAnIdentityThatCannotBeNamedThrows(\Closure $identity): void
    {
        $this->expectException(UnresolvedReferenceException::class);

        $this->references()->reference($identity());
    }

    /**
     * Store the identity keyed by the handle `alice`.
     *
     * @return \Tests\Fixtures\Sso\HandledIdentity
     */
    private function createHandled(): HandledIdentity
    {
        return HandledIdentity::query()->create(['id' => self::HANDLE]);
    }

    /**
     * Store an identity keyed by the UUID it generates, in lower case.
     *
     * @return \Tests\Fixtures\Sso\UuidIdentity
     */
    private function createUuid(): UuidIdentity
    {
        return UuidIdentity::query()->create();
    }

    /**
     * The translator, as the adapters resolve it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\IdentityReferences
     */
    private function references(): IdentityReferences
    {
        $references = $this->app?->make(IdentityReferences::class);

        self::assertInstanceOf(IdentityReferences::class, $references);

        return $references;
    }

    /**
     * Assert the reference resolves to nobody: it throws an unresolved
     * identity, naming its type.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $reference
     * @return void
     */
    private function assertUnresolved(IdentityReference $reference): void
    {
        try {
            $this->references()->identity($reference);

            self::fail('The reference was resolved.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString('[' . $reference->type . ']', $exception->getMessage());
        }
    }
}
