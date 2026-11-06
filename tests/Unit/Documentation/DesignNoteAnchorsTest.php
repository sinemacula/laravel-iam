<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the test anchors the design notes cite: every test method a
 * note's `Authoritative Tests` section names exists on each test class it
 * follows.
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
     * Read the anchors each item of the note's `Authoritative Tests` section
     * names, in order, an item being a bullet or a nested bullet.
     *
     * @param  string  $note
     * @return list<list<string>>
     */
    private function items(string $note): array
    {
        $contents = (string) file_get_contents(self::root() . '/' . $note);
        $section  = substr($contents, (int) strpos($contents, self::SECTION) + strlen(self::SECTION));
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
