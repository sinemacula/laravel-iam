<?php

declare(strict_types = 1);

namespace Tests\Unit\Install;

use Illuminate\Filesystem\Filesystem;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Install\MigrationLedger;
use Tests\Concerns\UsesScratchDirectory;

/**
 * Unit tests for recognising a member's published migration by its base name,
 * whatever its timestamp, and telling it from an application's own migration of
 * the same base name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationLedger::class)]
final class MigrationLedgerTest extends TestCase
{
    use UsesScratchDirectory;

    /** @var string The namespace the member's migrations name. */
    private const string MEMBER = 'SineMacula\Laravel\Mfa\\';

    /** @var string A member migration's contents. */
    private const string MEMBERS_MIGRATION = "<?php\n\nuse SineMacula\\Laravel\\Mfa\\Database\\StorageConnection;\n";

    /** @var string An application migration's contents. */
    private const string APPLICATIONS_MIGRATION = "<?php\n\nuse Illuminate\\Database\\Migrations\\Migration;\n";

    /**
     * Delete the test's directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->deleteScratch();

        parent::tearDown();
    }

    /**
     * Provide migration paths and their base names.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function baseNames(): iterable
    {
        yield 'a member timestamp' => ['/app/database/migrations/2026_04_15_000000_create_mfa_factors_table.php', 'create_mfa_factors_table'];
        yield 'another timestamp' => ['2019_12_31_235959_create_mfa_factors_table.php', 'create_mfa_factors_table'];
        yield 'no timestamp' => ['create_mfa_factors_table.php', 'create_mfa_factors_table'];
        yield 'a timestamp not at the start' => ['x_2026_04_15_000000_create.php', 'x_2026_04_15_000000_create'];
        yield 'a short timestamp' => ['2026_04_15_00000_create.php', '2026_04_15_00000_create'];
        yield 'only the first timestamp' => ['2026_04_15_000000_2026_04_15_000000_create.php', '2026_04_15_000000_create'];
    }

    /**
     * A migration's base name is its file name without its timestamp and its
     * extension.
     *
     * @param  string  $path
     * @param  string  $baseName
     * @return void
     */
    #[DataProvider('baseNames')]
    public function testTheBaseNameDropsTheTimestampAndTheExtension(string $path, string $baseName): void
    {
        self::assertSame($baseName, MigrationLedger::baseName($path));
    }

    /**
     * The member's migration published under another timestamp is its copy.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testACopyUnderAnotherTimestampIsRecognised(): void
    {
        $copy = $this->writeScratch('migrations/2020_01_01_000000_create_mfa_factors_table.php', self::MEMBERS_MIGRATION);

        $this->writeScratch('migrations/2020_01_01_000001_create_mfa_codes_table.php', self::MEMBERS_MIGRATION);

        $ledger = new MigrationLedger(new Filesystem);

        self::assertSame($copy, $ledger->copyOf($this->scratch('migrations/2026_04_15_000000_create_mfa_factors_table.php'), self::MEMBER));
        self::assertSame([], $ledger->namesakesOf($this->scratch('migrations/2026_04_15_000000_create_mfa_factors_table.php'), self::MEMBER));
    }

    /**
     * An application's own migration of the same base name, which names no
     * member namespace, is no copy: it is a namesake.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAnApplicationsMigrationOfTheSameBaseNameIsANamesake(): void
    {
        $namesake = $this->writeScratch('migrations/2019_01_01_000000_create_mfa_factors_table.php', self::APPLICATIONS_MIGRATION);
        $ledger   = new MigrationLedger(new Filesystem);
        $member   = $this->scratch('migrations/2026_04_15_000000_create_mfa_factors_table.php');

        self::assertNull($ledger->copyOf($member, self::MEMBER));
        self::assertSame([$namesake], $ledger->namesakesOf($member, self::MEMBER));
    }

    /**
     * A copy is found among namesakes, in file name order, and only the
     * namesakes that are not copies are reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testACopyIsFoundAmongNamesakes(): void
    {
        $first    = $this->writeScratch('migrations/2018_01_01_000000_create_mfa_factors_table.php', self::MEMBERS_MIGRATION);
        $namesake = $this->writeScratch('migrations/2019_01_01_000000_create_mfa_factors_table.php', self::APPLICATIONS_MIGRATION);

        $this->writeScratch('migrations/2021_01_01_000000_create_mfa_factors_table.php', self::MEMBERS_MIGRATION);

        $ledger = new MigrationLedger(new Filesystem);
        $member = $this->scratch('migrations/2026_04_15_000000_create_mfa_factors_table.php');

        self::assertSame($first, $ledger->copyOf($member, self::MEMBER));
        self::assertSame([$namesake], $ledger->namesakesOf($member, self::MEMBER));
    }

    /**
     * Only a directory's own `.php` files are migrations: a file of another
     * extension, or one in a directory below, is not read.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testOnlyTheDirectorysOwnPhpFilesAreRead(): void
    {
        $this->writeScratch('migrations/0000_notes.txt', self::MEMBERS_MIGRATION);
        $this->writeScratch('migrations/2020_01_01_000000_create_mfa_codes_table.php.bak', self::MEMBERS_MIGRATION);
        $this->writeScratch('migrations/archive/2020_01_01_000000_create_mfa_factors_table.php', self::MEMBERS_MIGRATION);

        $copy   = $this->writeScratch('migrations/2020_01_01_000001_create_mfa_codes_table.php', self::MEMBERS_MIGRATION);
        $ledger = new MigrationLedger(new Filesystem);
        $member = $this->scratch('migrations/2026_04_15_000000_create_mfa_factors_table.php');

        self::assertNull($ledger->copyOf($member, self::MEMBER));
        self::assertSame([], $ledger->namesakesOf($member, self::MEMBER));
        self::assertSame($copy, $ledger->copyOf($this->scratch('migrations/2026_04_15_000003_create_mfa_codes_table.php'), self::MEMBER));
        self::assertSame([], $ledger->namesakesOf($this->scratch('migrations/2026_04_15_000003_create_mfa_codes_table.php'), self::MEMBER));
    }

    /**
     * A directory that does not exist yet holds no migration.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testADirectoryThatDoesNotExistHoldsNone(): void
    {
        $ledger = new MigrationLedger(new Filesystem);

        self::assertNull($ledger->copyOf($this->scratch('missing/2026_04_15_000000_create_mfa_factors_table.php'), self::MEMBER));
    }

    /**
     * A directory is read once, when it is first asked about: a file written
     * there afterwards is not seen by the same ledger.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testADirectoryIsReadOnce(): void
    {
        $ledger = new MigrationLedger(new Filesystem);
        $member = $this->scratch('migrations/2026_04_15_000000_create_mfa_factors_table.php');

        self::assertNull($ledger->copyOf($member, self::MEMBER));

        $this->writeScratch('migrations/2026_04_15_000000_create_mfa_factors_table.php', self::MEMBERS_MIGRATION);

        self::assertNull($ledger->copyOf($member, self::MEMBER));
        self::assertSame($member, (new MigrationLedger(new Filesystem))->copyOf($member, self::MEMBER));
    }
}
