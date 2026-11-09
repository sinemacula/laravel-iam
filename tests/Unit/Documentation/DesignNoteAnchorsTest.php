<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the anchors the design notes cite: every test method a note's
 * `Authoritative Tests` section names exists on each test class it follows, and
 * every file its `Implementation Anchors` section names exists and defines the
 * symbols cited after it.
 *
 * Each item of a section names one or more test classes, by path or by class
 * name, and then the methods that hold the guarantee. Classes named one after
 * another, with no method between them, share the methods that follow them, so
 * each method must exist on every class it follows within its item. Anything
 * else an item names, such as a fixture, a contract kit or a value, leaves the
 * classes in force.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DesignNoteAnchorsTest extends TestCase
{
    /** @var string The heading of the section that cites the tests. */
    private const string SECTION = '## Authoritative Tests';

    /** @var string The heading of the section that cites the implementation. */
    private const string IMPLEMENTATION = '## Implementation Anchors';

    /** @var string The pattern a cited file matches, by path or, beside the file before it, by name. */
    private const string FILE = '/^(?:[\w.-]+\/)*[\w.-]+\.(?:php|json)$/';

    /** @var string The pattern a cited method, constant or property matches. */
    private const string SYMBOL = '/^(?:(?<method>\w+)\(\)|(?<constant>[A-Z][A-Z0-9_]*)|\$(?<property>\w+))$/';

    /** @var string The namespace the package's `src/` directory holds. */
    private const string SOURCE_NAMESPACE = 'SineMacula\Laravel\Iam\\';

    /** @var string The pattern a cited test method matches. */
    private const string METHOD = '/^test[A-Z]\w*$/';

    /** @var string The pattern a cited test class matches, by path or by name. */
    private const string TEST_CLASS = '/^(?:[\w\/]*\/)?[A-Z]\w*Test(?:\.php)?$/';

    /**
     * Provide every design note that cites tests.
     *
     * @return iterable<string, array{string}>
     */
    public static function notes(): iterable
    {
        foreach (glob(self::root() . '/docs/design/*.md') ?: [] as $path) {
            if (!str_contains((string) file_get_contents($path), self::SECTION)) {
                continue;
            }

            yield basename($path) => ['docs/design/' . basename($path)];
        }
    }

    /**
     * Every method a design note cites exists on each test class it follows.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('notes')]
    public function testEveryCitedMethodExistsOnEachClassItFollows(string $note): void
    {
        $missing   = [];
        $citations = 0;

        foreach ($this->items($note) as $item) {
            foreach ($this->citations($note, $item) as [$classes, $method]) {
                $missing = [...$missing, ...$this->missingFrom($classes, $method)];

                $citations++;
            }
        }

        self::assertGreaterThan(0, $citations, sprintf('%s cites no test method.', $note));
        self::assertSame([], $missing, sprintf('%s cites methods its test classes do not define.', $note));
    }

    /**
     * Provide every design note that cites its implementation.
     *
     * @return iterable<string, array{string}>
     */
    public static function implementedNotes(): iterable
    {
        foreach (glob(self::root() . '/docs/design/*.md') ?: [] as $path) {
            if (!str_contains((string) file_get_contents($path), self::IMPLEMENTATION)) {
                continue;
            }

            yield basename($path) => ['docs/design/' . basename($path)];
        }
    }

    /**
     * Every file a design note's `Implementation Anchors` section names exists,
     * and every method, constant or property cited after files is defined on
     * one of them.
     *
     * Files named one after another, with no symbol between them, are all in
     * force for the symbols that follow, and a file named by name alone sits
     * beside the file named before it in its item. Anything else an item names,
     * such as a configuration key, a value or a symbol qualified by its class,
     * is not checked, but a file named after it starts a new run of files as
     * one named after a symbol does.
     *
     * @param  string  $note
     * @return void
     */
    #[DataProvider('implementedNotes')]
    public function testEveryCitedSymbolIsDefinedOnAFileItFollows(string $note): void
    {
        $missing   = [];
        $citations = 0;

        foreach ($this->items($note, self::IMPLEMENTATION) as $item) {
            foreach ($this->symbols($note, $item) as [$files, $symbol]) {
                if (!$this->definesAny($files, $symbol)) {
                    $missing[] = sprintf('%s on %s', $symbol, $files === [] ? 'no file' : implode(', ', $files));
                }

                $citations++;
            }
        }

        self::assertGreaterThan(0, $citations, sprintf('%s cites no symbol of its implementation.', $note));
        self::assertSame([], $missing, sprintf('%s cites symbols the files it follows do not define.', $note));
    }

    /**
     * Read the anchors each item of one section of the note names, in order, an
     * item being a bullet or a nested bullet.
     *
     * @param  string  $note
     * @param  string  $heading
     * @return list<list<string>>
     */
    private function items(string $note, string $heading = self::SECTION): array
    {
        $contents = (string) file_get_contents(self::root() . '/' . $note);
        $section  = substr($contents, (int) strpos($contents, $heading) + strlen($heading));
        $next     = strpos($section, "\n## ");
        $section  = $next === false ? $section : substr($section, 0, $next);
        $items    = [];

        foreach (preg_split('/^\s*- /m', $section) ?: [] as $item) {
            preg_match_all('/`([^`]+)`/', $item, $matches);

            $items[] = $matches[1];
        }

        return $items;
    }

    /**
     * Pair each method an item cites with the test classes it follows.
     *
     * @param  string  $note
     * @param  list<string>  $item
     * @return list<array{array<string, string>, string}>
     */
    private function citations(string $note, array $item): array
    {
        $citations   = [];
        $classes     = [];
        $afterMethod = true;

        foreach ($item as $anchor) {
            if (preg_match(self::METHOD, $anchor) === 1) {
                $citations[] = [$classes, $anchor];
                $afterMethod = true;

                continue;
            }

            if (!str_contains($anchor, '*') && preg_match(self::TEST_CLASS, $anchor) !== 1) {
                continue;
            }

            $classes     = ($afterMethod ? [] : $classes) + $this->resolve($note, $anchor, $classes);
            $afterMethod = false;
        }

        return $citations;
    }

    /**
     * Pair each symbol an item cites with the files it follows, asserting that
     * every file the item names exists.
     *
     * @param  string  $note
     * @param  list<string>  $item
     * @return list<array{list<string>, string}>
     */
    private function symbols(string $note, array $item): array
    {
        $symbols     = [];
        $files       = [];
        $afterSymbol = true;

        foreach ($item as $anchor) {
            $isSymbol = preg_match(self::SYMBOL, $anchor) === 1;

            if ($isSymbol) {
                $symbols[] = [$files, $anchor];
            }

            if ($isSymbol || preg_match(self::FILE, $anchor) !== 1) {
                $afterSymbol = true;

                continue;
            }

            $files       = [...($afterSymbol ? [] : $files), $this->fileOf($note, $anchor, $files)];
            $afterSymbol = false;
        }

        return $symbols;
    }

    /**
     * Resolve a cited file to its path from the package root, a file named by
     * name alone sitting beside the last file in force, and assert it exists.
     *
     * @param  string  $note
     * @param  string  $anchor
     * @param  list<string>  $files
     * @return string
     */
    private function fileOf(string $note, string $anchor, array $files): string
    {
        $directory = $files                                   === [] ? '.' : dirname($files[count($files) - 1]);
        $file      = str_contains($anchor, '/') || $directory === '.' ? $anchor : $directory . '/' . $anchor;

        self::assertFileExists(self::root() . '/' . $file, sprintf('%s cites a file that does not exist.', $note));

        return $file;
    }

    /**
     * Determine whether any of the files defines the cited symbol: by
     * reflection for a class under `src/`, which finds what it inherits or
     * takes from a trait, and by its declaration in the file otherwise.
     *
     * @param  list<string>  $files
     * @param  string  $symbol
     * @return bool
     */
    private function definesAny(array $files, string $symbol): bool
    {
        preg_match(self::SYMBOL, $symbol, $parts);

        $kind = array_key_first(array_filter(
            array_intersect_key($parts, array_flip(['method', 'constant', 'property'])),
            static fn (string $name): bool => $name !== '',
        ));

        foreach ($files as $file) {
            if ($this->defines($file, (string) $kind, $parts[$kind] ?? '')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether one file defines the symbol of the kind named: a
     * `method`, a `constant` or a `property`.
     *
     * @param  string  $file
     * @param  string  $kind
     * @param  string  $name
     * @return bool
     */
    private function defines(string $file, string $kind, string $name): bool
    {
        $class = self::SOURCE_NAMESPACE . str_replace('/', '\\', substr($file, strlen('src/'), -strlen('.php')));

        if (str_starts_with($file, 'src/') && (class_exists($class) || interface_exists($class) || trait_exists($class))) {
            $reflection = new \ReflectionClass($class);

            return match ($kind) {
                'method'   => $reflection->hasMethod($name),
                'constant' => $reflection->hasConstant($name),
                default    => $reflection->hasProperty($name),
            };
        }

        $pattern = match ($kind) {
            'method'   => '/\bfunction\s+' . $name . '\s*\(/',
            'constant' => '/\b(?:const(?:\s+[\w|?\\\]+)?|case)\s+' . $name . '\b/',
            default    => '/\$' . $name . '\b/',
        };

        return preg_match($pattern, (string) file_get_contents(self::root() . '/' . $file)) === 1;
    }

    /**
     * List the classes a cited method is missing from, naming the method alone
     * when it follows no class.
     *
     * @param  array<string, string>  $classes
     * @param  string  $method
     * @return list<string>
     */
    private function missingFrom(array $classes, string $method): array
    {
        if ($classes === []) {
            return [sprintf('%s, which follows no test class', $method)];
        }

        $missing = array_filter($classes, static fn (string $class): bool => !method_exists($class, $method));

        return array_map(static fn (string $path): string => sprintf('%s::%s', $path, $method), array_keys($missing));
    }

    /**
     * Resolve a cited test class to its file under `tests/` and the class it
     * declares, by path or by name, preferring the directory of a class already
     * in force when the name is ambiguous; a pattern resolves to none.
     *
     * @param  string  $note
     * @param  string  $anchor
     * @param  array<string, string>  $classes
     * @return array<string, string>
     */
    private function resolve(string $note, string $anchor, array $classes): array
    {
        if (str_contains($anchor, '*')) {
            return [];
        }

        $file = str_ends_with($anchor, '.php') ? $anchor : $anchor . '.php';

        if (str_starts_with($file, 'tests/')) {
            self::assertFileExists(self::root() . '/' . $file, sprintf('%s cites a test file that does not exist.', $note));

            return [$file => $this->className($file)];
        }

        $candidates = array_values(array_filter($this->testFiles(), static fn (string $path): bool => str_ends_with($path, '/' . $file)));

        if (count($candidates) > 1) {
            $directories = array_map('dirname', array_keys($classes));
            $candidates  = array_values(array_filter($candidates, static fn (string $path): bool => in_array(dirname($path), $directories, true)));
        }

        self::assertCount(1, $candidates, sprintf('%s cites %s, which does not name exactly one test file.', $note, $anchor));

        return [$candidates[0] => $this->className($candidates[0])];
    }

    /**
     * List every test file under `tests/`, relative to the package root.
     *
     * @return list<string>
     */
    private function testFiles(): array
    {
        $files    = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::root() . '/tests', \FilesystemIterator::SKIP_DOTS));

        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !str_ends_with($file->getFilename(), 'Test.php')) {
                continue;
            }

            $files[] = substr($file->getPathname(), strlen(self::root()) + 1);
        }

        sort($files);

        return $files;
    }

    /**
     * Name the class a test file under `tests/` declares.
     *
     * @param  string  $path
     * @return string
     */
    private function className(string $path): string
    {
        return 'Tests\\' . str_replace('/', '\\', substr($path, strlen('tests/'), -strlen('.php')));
    }

    /**
     * Return the package root.
     *
     * @return string
     */
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }
}
