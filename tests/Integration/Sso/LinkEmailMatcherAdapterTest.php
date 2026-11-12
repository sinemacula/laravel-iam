<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\LinkEmailMatcherAdapter;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Machine;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\KeepsCase;
use Tests\Fixtures\Sso\Member;
use Tests\Fixtures\Sso\PlainVerifiableIdentity;
use Tests\Fixtures\Sso\ReplicatedMember;
use Tests\TestCase;

/**
 * Integration tests for matching SSO's asserted email against verified identity
 * emails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkEmailMatcherAdapter::class)]
final class LinkEmailMatcherAdapterTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The email address the person holds. */
    private const string EMAIL = 'ada@example.test';

    /** @var string The columns of the replicated members' table. */
    private const string REPLICATED_COLUMNS = 'id integer primary key autoincrement, email varchar(255) not null, email_verified_at datetime null,'
        . ' password varchar(255) null, created_at datetime null, updated_at datetime null';

    /** @var string The guard members sign in on. */
    private const string STAFF = 'staff';

    /**
     * Create the members' table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $caseless = DB::connection()->getDriverName() === 'sqlite';

        Schema::create(Member::TABLE, static function (Blueprint $table) use ($caseless): void {
            $table->id();

            $email = $table->string('email');

            if ($caseless) {
                $email->collation('nocase');
            }

            $table->timestamp('email_verified_at')->nullable();
            $table->string('password')->nullable();
            $table->timestamps();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::dropIfExists(Member::TABLE);
        });
    }

    /**
     * The adapter is the link email contract SSO resolves.
     *
     * @return void
     */
    public function testTheAdapterIsSsosLinkEmailMatcher(): void
    {
        self::assertInstanceOf(LinkEmailMatcherAdapter::class, $this->resolved(LinkEmailMatcher::class));
    }

    /**
     * Rows of the email as a provider might assert the person's.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAssertedForms(): iterable
    {
        yield 'as held' => [self::EMAIL];

        yield 'in another case' => ['Ada@Example.TEST'];

        yield 'with spaces around it' => ['  ada@example.test '];
    }

    /**
     * The one identity holding the normal form verified is exactly one match.
     *
     * @param  string  $asserted
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAssertedForms')]
    public function testTheOneVerifiedIdentityIsExactlyOneMatch(string $asserted): void
    {
        $person = $this->createVerifiedPerson(self::EMAIL);

        $this->createPerson();

        $match = $this->match($asserted);

        self::assertFalse($match->ambiguous);
        self::assertTrue($match->isSolely(self::referenceOf($person)));
    }

    /**
     * Only a verified address matches, at every isolation level.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testOnlyAVerifiedAddressMatches(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->createPerson(self::EMAIL);

        self::assertEquals(LinkEmailMatch::none(), $this->match(self::EMAIL));

        $verified = $this->createVerifiedPerson('grace@example.test');

        self::assertTrue($this->match('grace@example.test')->isSolely(self::referenceOf($verified)));
    }

    /**
     * No address is folded beyond the normaliser's form.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoAddressIsFoldedIntoAnother(): void
    {
        $this->createVerifiedPerson(self::EMAIL);

        foreach (['ada+sso@example.test', 'a.da@example.test', "\u{0430}da@example.test", 'ada@example.test.'] as $other) {
            self::assertEquals(LinkEmailMatch::none(), $this->match($other), $other);
        }
    }

    /**
     * An email the normaliser refuses names nobody, and nothing is queried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEmailTheNormaliserRefusesMatchesNobodyWithoutAQuery(): void
    {
        $this->createVerifiedPerson(self::EMAIL);

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertEquals(LinkEmailMatch::none(), $this->match('   '));
        self::assertEquals(LinkEmailMatch::none(), $this->match("ada\xFF@example.test"));
        self::assertSame(0, $queries);
    }

    /**
     * Two verified holders of the address are ambiguous.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTwoVerifiedIdentitiesAreAmbiguous(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->declareGuard(self::STAFF, 'members', Member::class);

        $person = $this->createVerifiedPerson(self::EMAIL);
        $member = Member::query()->create(['email' => self::EMAIL]);

        self::assertTrue($this->match(self::EMAIL)->isSolely(self::referenceOf($person)));

        $member->forceFill(['email_verified_at' => now()])->save();

        self::assertEquals(LinkEmailMatch::ambiguous(), $this->match(self::EMAIL));
    }

    /**
     * Each kind of identity is searched once, and guards naming no verifiable
     * identity are skipped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachKindOfIdentityIsSearchedOnce(): void
    {
        $this->declareGuard('second', 'people_again', Person::class);
        $this->declareGuard('machines', 'machines', Machine::class);
        $this->declareGuard('plain', 'plain', PlainVerifiableIdentity::class);
        $this->declareGuard('unnamed', 'nowhere', null);
        Config::set('auth.guards.sessionless', ['driver' => 'jwt']);
        Config::set('auth.guards.web', ['driver' => 'session', 'provider' => 'web_members']);
        Config::set('auth.providers.web_members', ['driver' => 'model', 'model' => Member::class]);

        $person = $this->createVerifiedPerson(self::EMAIL);
        $member = Member::query()->create(['email' => self::EMAIL]);

        self::assertTrue($this->match(self::EMAIL)->isSolely(self::referenceOf($person)));

        $member->forceFill(['email_verified_at' => now()])->save();

        self::assertTrue($this->match(self::EMAIL)->isSolely(self::referenceOf($person)), 'A guard of another driver signs no session in.');

        $this->declareGuard(self::STAFF, 'members', Member::class);

        self::assertEquals(LinkEmailMatch::ambiguous(), $this->match(self::EMAIL));
    }

    /**
     * Every holder within one kind of identity is judged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryHolderOfOneKindIsJudged(): void
    {
        $this->declareGuard(self::STAFF, 'members', Member::class);

        Member::query()->create(['email' => self::EMAIL]);

        $verified = Member::query()->create(['email' => self::EMAIL, 'email_verified_at' => now()]);

        self::assertTrue($this->match(self::EMAIL)->isSolely((new IdentityReferences)->reference($verified)));

        Member::query()->create(['email' => self::EMAIL, 'email_verified_at' => now()]);

        self::assertEquals(LinkEmailMatch::ambiguous(), $this->match(self::EMAIL));
    }

    /**
     * An address a case-insensitive collation merely matches is no match.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAddressACollationMerelyMatchesIsNoMatch(): void
    {
        $this->app?->instance(KeepsCase::class, new KeepsCase);

        Config::set('authentication.identifiers.normalizers.email', KeepsCase::class);

        $this->declareGuard(self::STAFF, 'members', Member::class);

        $member = Member::query()->create(['email' => 'Ada@example.test', 'email_verified_at' => now()]);

        self::assertEquals(LinkEmailMatch::none(), $this->match(self::EMAIL));
        self::assertTrue($this->match('Ada@example.test')->isSolely((new IdentityReferences)->reference($member)));
    }

    /**
     * The identities are read on the write connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentitiesAreReadOnTheWriteConnection(): void
    {
        Config::set('database.connections.' . ReplicatedMember::CONNECTION, [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
            'read'     => ['database' => ':memory:'],
            'write'    => ['database' => ':memory:'],
        ]);

        $connection = DB::connection(ReplicatedMember::CONNECTION);

        foreach ([$connection->getPdo(), $connection->getReadPdo()] as $pdo) {
            $pdo->exec('create table ' . ReplicatedMember::TABLE . ' (' . self::REPLICATED_COLUMNS . ')');
        }

        $this->declareGuard(self::STAFF, 'replicated_members', ReplicatedMember::class);

        $member = ReplicatedMember::query()->create(['email' => self::EMAIL, 'email_verified_at' => now()]);

        self::assertNull(ReplicatedMember::query()->first(), 'The replica must lag the primary for this test to prove anything.');
        self::assertTrue($this->match(self::EMAIL)->isSolely((new IdentityReferences)->reference($member)));
    }

    /**
     * Ask the adapter for the asserted email.
     *
     * @param  string  $email
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function match(string $email): LinkEmailMatch
    {
        return ($this->app ?? self::fail('The application has not booted.'))->make(LinkEmailMatcher::class)->match(new LinkEmailQuery('tenant-1', $email, 'example.test'));
    }

    /**
     * Create a person whose email address is the one given, verified.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Models\Person
     */
    private function createVerifiedPerson(string $email): Person
    {
        $person = $this->createPerson($email);

        $person->forceFill(['email_verified_at' => now()])->save();

        return $person;
    }

    /**
     * Declare a session guard over the model, or a provider naming no model.
     *
     * @param  string  $guard
     * @param  string  $provider
     * @param  ?class-string  $model
     * @return void
     */
    private function declareGuard(string $guard, string $provider, ?string $model): void
    {
        Config::set('auth.guards.' . $guard, ['driver' => 'jwt', 'provider' => $provider]);
        Config::set('auth.providers.' . $provider, $model === null ? ['driver' => 'model'] : ['driver' => 'model', 'model' => $model]);
    }

    /**
     * The reference SSO names the identity by.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function referenceOf(Person $person): IdentityReference
    {
        return (new IdentityReferences)->reference($person);
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
