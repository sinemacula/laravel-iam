<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;

/**
 * Unit tests for what audit-log's own capture must leave alone (IAM-9.6,
 * IAM-2.5): every `jwt` and `api_key` guard, found by its driver, in
 * `audit-log.capture.laravel.except_guards`, and Gate capture off. It only
 * computes, for `iam:check` to enforce, and writes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureExclusions::class)]
final class CaptureExclusionsTest extends TestCase
{
    /** @var array<string, array<string, mixed>> The guards of an application with both of the package's drivers and two of Laravel's. */
    private const array GUARDS = [
        'web'      => ['driver' => 'session', 'provider' => 'users'],
        'api'      => ['driver' => 'jwt', 'provider' => 'people'],
        'partners' => ['driver' => 'api_key', 'provider' => 'partners'],
        'mobile'   => ['driver' => 'jwt', 'provider' => 'people'],
        'tokens'   => ['driver' => 'token', 'provider' => 'users'],
    ];

    /**
     * The keys are audit-log's own, and the drivers are
     * `laravel-authentication`'s.
     *
     * @return void
     */
    public function testTheKeysAreAuditLogsAndTheDriversAuthentications(): void
    {
        self::assertSame('audit-log.capture.laravel.except_guards', CaptureExclusions::EXCEPT_GUARDS_KEY);
        self::assertSame('audit-log.capture.gate.enabled', CaptureExclusions::GATE_KEY);
        self::assertSame(['jwt', 'api_key'], CaptureExclusions::DRIVERS);
        self::assertSame('*', CaptureExclusions::ALL_GUARDS);
    }

    /**
     * Every guard of either driver is found, in the order the application
     * configures them, and no guard of any other driver.
     *
     * @return void
     */
    public function testEveryJwtAndApiKeyGuardIsFoundInOrder(): void
    {
        self::assertSame(['api', 'partners', 'mobile'], self::exclusions()->guards());
    }

    /**
     * Rows of `[guards]` holding no guard of either driver.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideNoPackageGuards(): iterable
    {
        yield 'no guards' => [[]];

        yield 'guards that are no list' => ['api'];

        yield 'only Laravel\'s drivers' => [['web' => ['driver' => 'session']]];

        yield 'a guard configured as no array' => [['api' => 'jwt']];

        yield 'a guard naming no driver' => [['api' => ['provider' => 'people']]];

        yield 'a driver that is no name' => [['api' => ['driver' => ['jwt']]]];
    }

    /**
     * An application with no guard of either driver has nothing to exclude.
     *
     * @param  mixed  $guards
     * @return void
     */
    #[DataProvider('provideNoPackageGuards')]
    public function testNoPackageGuardLeavesNothingToExclude(mixed $guards): void
    {
        $exclusions = new CaptureExclusions(new Repository(['auth' => ['guards' => $guards]]));

        self::assertSame([], $exclusions->guards());
        self::assertSame([], $exclusions->unexcludedGuards());
        self::assertSame([], $exclusions->exceptGuards());
    }

    /**
     * A guard whose configured name is a number is named by its digits.
     *
     * @return void
     */
    public function testAGuardNamedByANumberIsNamedByItsDigits(): void
    {
        self::assertSame(['7'], (new CaptureExclusions(new Repository(['auth' => ['guards' => [7 => ['driver' => 'jwt']]]])))->guards());
    }

    /**
     * With nothing excluded, every guard of either driver is missing, and the
     * exclusions to write are all of them.
     *
     * @return void
     */
    public function testWithNothingExcludedEveryPackageGuardIsMissing(): void
    {
        $exclusions = self::exclusions();

        self::assertSame(['api', 'partners', 'mobile'], $exclusions->unexcludedGuards());
        self::assertSame(['api', 'partners', 'mobile'], $exclusions->exceptGuards());
        self::assertFalse($exclusions->holds());
    }

    /**
     * The exclusions to write keep every guard the application excludes, in its
     * order, its own guards included, and add only those still missing.
     *
     * @return void
     */
    public function testTheExclusionsKeepTheApplicationsAndAddTheMissing(): void
    {
        $exclusions = self::exclusions(['audit-log' => ['capture' => ['laravel' => ['except_guards' => ['web', 'mobile']]]]]);

        self::assertSame(['api', 'partners'], $exclusions->unexcludedGuards());
        self::assertSame(['web', 'mobile', 'api', 'partners'], $exclusions->exceptGuards());
    }

    /**
     * Once every guard of either driver is excluded, none is missing and the
     * exclusions are what the application holds.
     *
     * @return void
     */
    public function testEveryGuardExcludedLeavesNoneMissing(): void
    {
        $exclusions = self::exclusions(['audit-log' => ['capture' => ['laravel' => ['except_guards' => ['partners', 'mobile', 'api']]]]]);

        self::assertSame([], $exclusions->unexcludedGuards());
        self::assertSame(['partners', 'mobile', 'api'], $exclusions->exceptGuards());
        self::assertTrue($exclusions->holds());
    }

    /**
     * Excluding every guard (`['*']`) leaves none missing, and is kept as it
     * is.
     *
     * @return void
     */
    public function testExcludingEveryGuardIsKept(): void
    {
        $exclusions = self::exclusions(['audit-log' => ['capture' => ['laravel' => ['except_guards' => ['*']]]]]);

        self::assertSame([], $exclusions->unexcludedGuards());
        self::assertSame(['*'], $exclusions->exceptGuards());
        self::assertTrue($exclusions->holds());
    }

    /**
     * Rows of `[except_guards]` that are no list of guard names.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedExclusions(): iterable
    {
        yield 'null' => [null];

        yield 'a name alone' => ['api'];

        yield 'a map' => [['api' => 'api']];

        yield 'a number' => [[1]];

        yield 'empty text' => [['']];

        yield 'every guard beside a name' => [['*', 'api']];
    }

    /**
     * An exclusion list that is no list of guard names is refused, naming the
     * key and never the value, rather than replaced or read as excluding
     * nothing.
     *
     * @param  mixed  $excepted
     * @return void
     */
    #[DataProvider('provideMalformedExclusions')]
    public function testAMalformedExclusionListIsRefused(mixed $excepted): void
    {
        $exclusions = self::exclusions(['audit-log' => ['capture' => ['laravel' => ['except_guards' => $excepted]]]]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.capture.laravel.except_guards` must be a list of guard names, or [\'*\'].');

        $exclusions->exceptGuards();
    }

    /**
     * A malformed exclusion list refuses the check of missing guards too.
     *
     * @return void
     */
    public function testAMalformedExclusionListRefusesTheCheck(): void
    {
        $exclusions = self::exclusions(['audit-log' => ['capture' => ['laravel' => ['except_guards' => 'api']]]]);

        $this->expectException(\InvalidArgumentException::class);

        $exclusions->holds();
    }

    /**
     * Rows of `[gate.enabled, off]`: off only while it is `false`.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideGateSettings(): iterable
    {
        yield 'false' => [false, true];

        yield 'true' => [true, false];

        yield 'text audit-log refuses' => ['false', false];

        yield 'a number audit-log refuses' => [0, false];

        yield 'null audit-log refuses' => [null, false];
    }

    /**
     * Gate capture is off only while its flag is `false`: anything else, a
     * value audit-log refuses among them, is not off.
     *
     * @param  mixed  $enabled
     * @param  bool  $off
     * @return void
     */
    #[DataProvider('provideGateSettings')]
    public function testGateCaptureIsOffOnlyWhileFalse(mixed $enabled, bool $off): void
    {
        $exclusions = self::exclusions([
            'audit-log' => ['capture' => ['laravel' => ['except_guards' => ['*']], 'gate' => ['enabled' => $enabled]]],
        ]);

        self::assertSame($off, $exclusions->isGateCaptureOff());
        self::assertSame($off, $exclusions->holds());
    }

    /**
     * Gate capture left unset is off, audit-log's default.
     *
     * @return void
     */
    public function testGateCaptureLeftUnsetIsOff(): void
    {
        self::assertTrue(self::exclusions()->isGateCaptureOff());
    }

    /**
     * Everything is read when it is asked for: a guard configured, or an
     * exclusion written, after the exclusions were built counts.
     *
     * @return void
     */
    public function testEverythingIsReadWhenAsked(): void
    {
        $config     = new Repository(['auth' => ['guards' => self::GUARDS]]);
        $exclusions = new CaptureExclusions($config);

        self::assertFalse($exclusions->holds());

        $config->set('auth.guards.devices', ['driver' => 'api_key']);
        $config->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['api', 'partners', 'mobile']);

        self::assertSame(['devices'], $exclusions->unexcludedGuards());

        $config->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['api', 'partners', 'mobile', 'devices']);
        $config->set(CaptureExclusions::GATE_KEY, true);

        self::assertSame([], $exclusions->unexcludedGuards());
        self::assertFalse($exclusions->holds());
    }

    /**
     * Computing the exclusions writes no configuration.
     *
     * @return void
     */
    public function testNothingIsWritten(): void
    {
        $config     = new Repository(['auth' => ['guards' => self::GUARDS]]);
        $before     = $config->all();
        $exclusions = new CaptureExclusions($config);

        $exclusions->exceptGuards();
        $exclusions->holds();

        self::assertSame($before, $config->all());
    }

    /**
     * The exclusions over the given configuration, the guards of an application
     * with both of the package's drivers unless it names its own.
     *
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Iam\Audit\CaptureExclusions
     */
    private static function exclusions(array $config = []): CaptureExclusions
    {
        return new CaptureExclusions(new Repository(array_replace_recursive(['auth' => ['guards' => self::GUARDS]], $config)));
    }
}
