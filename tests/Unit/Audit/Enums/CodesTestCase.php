<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Enums;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;

/**
 * The checks every enum of this package's codes is held to (IAM-9.2, IAM-9.3):
 * every code is under its member's reserved prefix and is none audit-log
 * ships; every definition is version 1, in its category, keeping exactly the
 * properties its case lists, each as it says, and dropping every other; and
 * audit-log's catalogue takes the enum, twice over, refusing none of it.
 *
 * Each subclass names its enum, its prefixes and, for every case, the category
 * and the properties it keeps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class CodesTestCase extends TestCase
{
    /**
     * Every code is pinned, and nothing more.
     *
     * @return void
     */
    public function testEveryCodeIsPinned(): void
    {
        static::assertSame(array_keys(static::expected()), array_map(static fn (\BackedEnum $case): string => (string) $case->value, static::enum()::cases()));
    }

    /**
     * Rows of `[case]` of the enum.
     *
     * @return iterable<string, array{0: \BackedEnum&\SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties}>
     */
    public static function provideCases(): iterable
    {
        foreach (static::enum()::cases() as $case) {
            yield (string) $case->value => [$case];
        }
    }

    /**
     * Each code is under one of its member's reserved prefixes, and none is one
     * audit-log ships.
     *
     * @param  \BackedEnum&\SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties  $case
     * @return void
     */
    #[DataProvider('provideCases')]
    public function testEachCodeIsUnderItsPrefixAndNoneIsAuditLogs(\BackedEnum&ListsProperties $case): void
    {
        $code     = (string) $case->value;
        $prefixed = array_filter(static::prefixes(), static fn (string $prefix): bool => str_starts_with($code, $prefix));

        static::assertCount(1, $prefixed);
        static::assertNull(CapturedActivity::tryFrom($code));
        static::assertSame($code, EventCode::of($code)->value);
    }

    /**
     * Each definition is its own code's, version 1, in its category, keeping
     * exactly what it lists, as it says, and dropping every other property.
     *
     * @param  \BackedEnum&\SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties  $case
     * @return void
     */
    #[DataProvider('provideCases')]
    public function testEachDefinitionKeepsExactlyWhatItLists(\BackedEnum&ListsProperties $case): void
    {
        [$category, $kept] = static::expected()[(string) $case->value];

        $definition = $case->definition();
        $rules      = array_map(static fn (FieldRule $rule): FieldHandling => $rule->handling, $definition->rules);

        ksort($kept, SORT_STRING);

        static::assertSame((string) $case->value, $definition->code);
        static::assertSame(1, $definition->version);
        static::assertSame($category, $definition->category);
        static::assertSame(FieldHandling::DROP, $definition->unlisted);
        static::assertSame($kept, $rules);
        static::assertEqualsCanonicalizing(array_keys($kept), $case->properties());
    }

    /**
     * Audit-log's catalogue takes every case, beside its own codes, and takes
     * it again unchanged.
     *
     * @return void
     */
    public function testTheCatalogueTakesTheEnumTwice(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(CapturedActivity::class);
        $catalogue->define(static::enum());
        $catalogue->define(static::enum());

        foreach (static::enum()::cases() as $case) {
            static::assertTrue($catalogue->definitionFor(EventCode::of($case), true)->equals($case->definition()));
        }
    }

    /**
     * The enum under test.
     *
     * @return class-string<\BackedEnum&\SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties>
     */
    abstract protected static function enum(): string;

    /**
     * The reserved prefixes its codes are under.
     *
     * @return list<string>
     */
    abstract protected static function prefixes(): array;

    /**
     * Each code, with its category and what it keeps: each property's path and
     * how it is kept.
     *
     * @return array<string, array{0: string, 1: array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>}>
     */
    abstract protected static function expected(): array;

    /**
     * Each of the properties given kept as captured.
     *
     * @param  string  ...$paths
     * @return array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>
     */
    protected static function retained(string ...$paths): array
    {
        return array_fill_keys($paths, FieldHandling::RETAIN);
    }

    /**
     * Each of the properties given kept only as a keyed hash.
     *
     * @param  string  ...$paths
     * @return array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>
     */
    protected static function pseudonymised(string ...$paths): array
    {
        return array_fill_keys($paths, FieldHandling::PSEUDONYMISE);
    }
}
