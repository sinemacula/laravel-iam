<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use Composer\Autoload\ClassLoader;
use Illuminate\Support\Arr;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\IamManager;

/**
 * Unit tests for the names the guides use: every guide's relative links and the
 * headings they point at exist, every class, interface, trait, enum or
 * namespace of the suite or of Laravel a guide names exists, every call on the
 * `Iam` facade is a public method of the manager, and every `iam.*`
 * configuration key and `IAM_*` environment variable a guide names is one
 * `config/iam.php` holds.
 *
 * The guides are written for the application developer, and every snippet in
 * them uses real names, so a name a release renames or removes fails here
 * rather than reaching a reader.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class GuideReferencesTest extends TestCase
{
    /** @var string The pattern of a name in the suite's or Laravel's namespaces. */
    private const string QUALIFIED_NAME = '/(?<![\w\\\])(?:SineMacula\\\Laravel|Illuminate)(?:\\\[A-Za-z_]\w*)+/';

    /** @var string The pattern of a span of inline code. */
    private const string INLINE_CODE = '/`([^`\n]+)`/';

    /** @var string The pattern of a name relative to a namespace, of two segments or more. */
    private const string RELATIVE_NAME = '/(?<![\w\\\])[A-Z]\w*(?:\\\[A-Za-z_]\w*)+/';

    /** @var string The namespace the guides name the suite's classes relative to. */
    private const string SUITE_ROOT = 'SineMacula\Laravel\\';

    /** @var list<string> The first segment of every name relative to the suite's root: one member's or this package's. */
    private const array SUITE_MEMBERS = ['Iam', 'Authentication', 'Mfa', 'Sso', 'AuditLog', 'Authorization'];

    /** @var array<string, string> The guides that name classes relative to a root of their own besides the suite's, with that root. */
    private const array GUIDE_ROOTS = ['docs/guides/testing.md' => 'SineMacula\Laravel\Iam\Testing\\'];

    /** @var string The pattern of a call on the `Iam` facade. */
    private const string FACADE_CALL = '/\bIam::(\w+)\(/';

    /** @var string The pattern of an `iam.*` configuration key, quoted as code. */
    private const string CONFIGURATION_KEY = '/`iam\.([a-z_]+(?:\.[a-z_]+)*)`/';

    /** @var string The pattern of an `IAM_*` environment variable. */
    private const string ENVIRONMENT_VARIABLE = '/\bIAM_[A-Z_]+\b/';

    /** @var string The pattern of an inline link's target. */
    private const string INLINE_LINK = '/\]\(([^)\s]+)\)/';

    /** @var string The pattern of an ATX heading, capturing its text. */
    private const string ATX_HEADING = '/^#{1,6}\s+(.+?)\s*#*\s*$/m';

    /** @var string The pattern of a Setext heading, capturing its text. */
    private const string SETEXT_HEADING = '/^([^\s|#>\-*+`][^\n]*)\n(?:=+|-+)[ \t]*$/m';

    /** @var string The pattern of a reference link's definition. */
    private const string REFERENCE_LINK = '/^\[[^\]]+\]:\s+(\S+)/m';

    /**
     * There are guides to check.
     *
     * @return void
     */
    public function testThereAreGuides(): void
    {
        self::assertNotSame([], iterator_to_array(self::guides()));
    }

    /**
     * Provide every guide.
     *
     * @return iterable<string, array{string}>
     */
    public static function guides(): iterable
    {
        foreach (glob(self::root() . '/docs/guides/*.md') ?: [] as $path) {
            yield basename($path) => ['docs/guides/' . basename($path)];
        }
    }

    /**
     * Every relative link of a guide names a file that exists, and every
     * heading it points at exists in that file.
     *
     * @param  string  $guide
     * @return void
     */
    #[DataProvider('guides')]
    public function testEveryRelativeLinkResolves(string $guide): void
    {
        $prose  = $this->prose($guide);
        $broken = [];

        preg_match_all(self::INLINE_LINK, $prose, $inline);
        preg_match_all(self::REFERENCE_LINK, $prose, $references);

        foreach ([...$inline[1], ...$references[1]] as $target) {
            if (preg_match('/^[a-z][a-z0-9+.-]*:/i', $target) === 1) {
                continue;
            }

            $problem = $this->problemWith($guide, $target);

            if ($problem === null) {
                continue;
            }

            $broken[] = $problem;
        }

        self::assertSame([], $broken, sprintf('%s links to what does not exist.', $guide));
    }

    /**
     * Every heading and link of a guide is one the link check reads as GitHub
     * renders it, so an anchor or a link cannot pass, or go unchecked, because
     * the check reads Markdown GitHub reads otherwise.
     *
     * @param  string  $guide
     * @return void
     */
    #[DataProvider('guides')]
    public function testEveryHeadingIsOneTheAnchorsAreDerivedFrom(string $guide): void
    {
        self::assertSame([], self::unsupported($this->prose($guide)), sprintf('%s uses Markdown the link check does not read.', $guide));
    }

    /**
     * A repeated heading is numbered as GitHub numbers it, on past a slug a
     * numbered heading already took, so no two headings share an anchor.
     *
     * @return void
     */
    public function testRepeatedHeadingsAreNumberedAsGitHubNumbersThem(): void
    {
        $prose = "# Foo\n\n## Foo\n\n## Foo 1\n\n### Foo\n\n## The `iam.*` keys: one, two\n";

        self::assertSame(['foo', 'foo-1', 'foo-1-1', 'foo-2', 'the-iam-keys-one-two'], self::anchorsOf($prose));
    }

    /**
     * Markdown the link check does not read is reported: a Setext heading, a
     * heading holding a link or HTML, and a link with a title.
     *
     * @return void
     */
    public function testMarkdownTheCheckDoesNotReadIsReported(): void
    {
        $prose = "Setext\n======\n\n## See [the guide](README.md)\n\n## A <span>tag</span>\n\nRead [it](README.md \"Title\").\n\n| a | b |\n|---|---|\n";

        self::assertSame([
            'Setext heading: Setext',
            'Heading with a link, an image or HTML: See [the guide](README.md)',
            'Heading with a link, an image or HTML: A <span>tag</span>',
            'An inline link with a title, a space or angle brackets in its target.',
        ], self::unsupported($prose));
    }

    /**
     * Every class, interface, trait, enum or namespace of the suite or of
     * Laravel a guide names exists.
     *
     * @param  string  $guide
     * @return void
     */
    #[DataProvider('guides')]
    public function testEveryQualifiedNameExists(string $guide): void
    {
        preg_match_all(self::QUALIFIED_NAME, $this->contents($guide), $matches);

        $missing = array_values(array_unique(array_filter(
            $matches[0],
            fn (string $name): bool => !$this->exists($name),
        )));

        self::assertSame([], $missing, sprintf('%s names classes or namespaces that do not exist.', $guide));
    }

    /**
     * Every class, interface, trait, enum or namespace a guide names in its
     * prose relative to `SineMacula\Laravel\` (`Mfa\Contracts\StepUp`, say), or
     * relative to the root a guide states for its own names, exists.
     *
     * @param  string  $guide
     * @return void
     */
    #[DataProvider('guides')]
    public function testEveryRelativeNameExists(string $guide): void
    {
        self::assertSame([], $this->missingRelativeNames($this->prose($guide), $guide), sprintf('%s names classes or namespaces that do not exist.', $guide));
    }

    /**
     * A relative name that resolves to nothing under the suite's root, or under
     * the root a guide states, is reported; one that resolves under either is
     * not, nor is a name the suite's members do not begin, nor one fully
     * qualified, which the qualified names' check reads.
     *
     * @return void
     */
    public function testARelativeNameThatResolvesToNothingIsReported(): void
    {
        $prose = 'See `Mfa\Translation\ProviderTrust`, `Iam\Mfa\Translation\ProviderTrust`, `Sso\Connections\EvidenceSettingsService`, '
            . '`Seams\MembershipsContract::assertDeterministic()`, `Seams\Retired`, `App\Models\User` and `SineMacula\Laravel\Mfa\Retired`.';

        self::assertSame(['Mfa\Translation\ProviderTrust'], $this->missingRelativeNames($prose, 'docs/guides/bindings.md'));
        self::assertSame(['Mfa\Translation\ProviderTrust', 'Seams\Retired'], $this->missingRelativeNames($prose, 'docs/guides/testing.md'));
    }

    /**
     * Every call on the `Iam` facade a guide makes is a public method of the
     * manager behind it.
     *
     * @param  string  $guide
     * @return void
     */
    #[DataProvider('guides')]
    public function testEveryFacadeCallIsTheManagers(string $guide): void
    {
        preg_match_all(self::FACADE_CALL, $this->contents($guide), $matches);

        $missing = array_values(array_unique(array_filter(
            $matches[1],
            static fn (string $method): bool => !method_exists(IamManager::class, $method)
                || !(new \ReflectionMethod(IamManager::class, $method))->isPublic(),
        )));

        self::assertSame([], $missing, sprintf('%s calls methods the IAM manager does not have.', $guide));
    }

    /**
     * Every `iam.*` key a guide names is a key of `config/iam.php`, and every
     * `IAM_*` variable one the file reads.
     *
     * @param  string  $guide
     * @return void
     */
    #[DataProvider('guides')]
    public function testEveryConfigurationNameIsThePackages(string $guide): void
    {
        $contents      = $this->contents($guide);
        $configuration = (string) file_get_contents(self::root() . '/config/iam.php');

        /** @var array<string, mixed> $keys */
        $keys = require self::root() . '/config/iam.php';

        preg_match_all(self::CONFIGURATION_KEY, $contents, $paths);
        preg_match_all(self::ENVIRONMENT_VARIABLE, $contents, $variables);

        $missing = [
            ...array_map(static fn (string $path): string => 'iam.' . $path, array_filter($paths[1], static fn (string $path): bool => !Arr::has($keys, $path))),
            ...array_filter($variables[0], static fn (string $variable): bool => !str_contains($configuration, sprintf('env(\'%s\'', $variable))),
        ];

        self::assertSame([], array_values(array_unique($missing)), sprintf('%s names configuration the package does not have.', $guide));
    }

    /**
     * The names the prose's inline code spans name relative to the suite's
     * root, or to the root the guide states for its own names, that resolve to
     * nothing under either. A name whose first segment is neither a member nor
     * a namespace or class under the guide's own root is no name of the
     * suite's, and is not read.
     *
     * @param  string  $prose
     * @param  string  $guide
     * @return list<string>
     */
    private function missingRelativeNames(string $prose, string $guide): array
    {
        $own     = self::GUIDE_ROOTS[$guide] ?? null;
        $missing = [];

        preg_match_all(self::INLINE_CODE, $prose, $spans);
        preg_match_all(self::RELATIVE_NAME, implode("\n", $spans[1]), $names);

        foreach ($names[0] as $name) {
            $roots = $this->rootsOf($name, $own);

            if ($roots === [] || array_filter($roots, fn (string $root): bool => $this->exists($root . $name)) !== []) {
                continue;
            }

            $missing[] = $name;
        }

        return array_values(array_unique($missing));
    }

    /**
     * The roots a relative name may be read under: the suite's when its first
     * segment is a member's or this package's, and the guide's own when its
     * first segment is a class or namespace there; none when it is no name of
     * the suite's.
     *
     * @param  string  $name
     * @param  ?string  $own
     * @return list<string>
     */
    private function rootsOf(string $name, ?string $own): array
    {
        $first = explode('\\', $name, 2)[0];
        $roots = in_array($first, self::SUITE_MEMBERS, true) ? [self::SUITE_ROOT] : [];

        if ($own !== null && $this->exists($own . $first)) {
            $roots[] = $own;
        }

        return $roots;
    }

    /**
     * Describe what is wrong with a relative link of a guide, or nothing when
     * it resolves.
     *
     * @param  string  $guide
     * @param  string  $target
     * @return ?string
     */
    private function problemWith(string $guide, string $target): ?string
    {
        [$path, $anchor] = array_pad(explode('#', $target, 2), 2, null);

        $file = $path === '' ? $guide : $this->normalise(dirname($guide) . '/' . $path);

        if (!file_exists(self::root() . '/' . $file)) {
            return sprintf('%s (no such file)', $target);
        }

        if ($anchor === null || !str_ends_with($file, '.md')) {
            return null;
        }

        return in_array($anchor, $this->anchors($file), true) ? null : sprintf('%s (no such heading)', $target);
    }

    /**
     * The anchors of every heading of a Markdown file, as GitHub derives them,
     * a repeated heading's numbered.
     *
     * @param  string  $file
     * @return list<string>
     */
    private function anchors(string $file): array
    {
        return self::anchorsOf($this->prose($file));
    }

    /**
     * The anchors of every ATX heading of the prose, as GitHub derives them:
     * lower-cased, with everything but letters, marks, numbers, spaces,
     * underscores and hyphens dropped and each space a hyphen, and a slug
     * already taken numbered on from the count of its own, again until it is
     * one not yet taken, so `Foo`, `Foo` and `Foo 1` are `foo`, `foo-1` and
     * `foo-1-1`. Only the subset
     * `testEveryHeadingIsOneTheAnchorsAreDerivedFrom()` allows is read: Setext
     * headings and headings holding links or HTML are refused there rather than
     * slugged here.
     *
     * @param  string  $prose
     * @return list<string>
     */
    private static function anchorsOf(string $prose): array
    {
        $anchors = [];
        $counts  = [];

        preg_match_all(self::ATX_HEADING, $prose, $headings);

        foreach ($headings[1] as $heading) {
            $base = str_replace(' ', '-', (string) preg_replace('/[^\p{L}\p{M}\p{N} _-]/u', '', mb_strtolower($heading)));
            $slug = $base;

            while (isset($counts[$slug])) {
                $counts[$base]++;
                $slug = sprintf('%s-%d', $base, $counts[$base]);
            }

            $counts[$slug] = 0;
            $anchors[]     = $slug;
        }

        return $anchors;
    }

    /**
     * What in the prose falls outside the Markdown the link and anchor checks
     * read: a Setext heading, a heading holding a link, an image or HTML, whose
     * anchor GitHub derives from its rendered text, and a link that is not a
     * plain inline `[text](target)` with no title.
     *
     * @param  string  $prose
     * @return list<string>
     */
    private static function unsupported(string $prose): array
    {
        $problems = [];

        preg_match_all(self::SETEXT_HEADING, $prose, $setext);
        preg_match_all(self::ATX_HEADING, $prose, $headings);

        foreach ($setext[1] as $heading) {
            $problems[] = sprintf('Setext heading: %s', $heading);
        }

        foreach ($headings[1] as $heading) {
            if (preg_match('/[\[\]<>]/', $heading) !== 1) {
                continue;
            }

            $problems[] = sprintf('Heading with a link, an image or HTML: %s', $heading);
        }

        if (substr_count($prose, '](') !== preg_match_all(self::INLINE_LINK, $prose)) {
            $problems[] = 'An inline link with a title, a space or angle brackets in its target.';
        }

        return $problems;
    }

    /**
     * Whether a qualified name is a class, interface, trait or enum, or a
     * namespace one of the autoloaded packages maps to a directory.
     *
     * @param  string  $name
     * @return bool
     */
    private function exists(string $name): bool
    {
        if (class_exists($name) || interface_exists($name) || trait_exists($name) || enum_exists($name)) {
            return true;
        }

        $namespace = $name . '\\';

        foreach ($this->namespaceRoots() as $prefix => $directory) {
            if (str_starts_with($namespace, $prefix) && is_dir($directory . '/' . str_replace('\\', '/', substr($namespace, strlen($prefix))))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every PSR-4 prefix the registered autoloaders map, each with one of its
     * directories, the directory's trailing separator dropped.
     *
     * @return iterable<string, string>
     */
    private function namespaceRoots(): iterable
    {
        foreach (ClassLoader::getRegisteredLoaders() as $loader) {
            foreach ($loader->getPrefixesPsr4() as $prefix => $directories) {
                foreach ($directories as $directory) {
                    yield $prefix => rtrim($directory, '/');
                }
            }
        }
    }

    /**
     * Resolve the `.` and `..` segments of a path relative to the package root.
     *
     * @param  string  $path
     * @return string
     */
    private function normalise(string $path): string
    {
        $segments = [];

        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            if ($segment === '..') {
                array_pop($segments);

                continue;
            }

            $segments[] = $segment;
        }

        return implode('/', $segments);
    }

    /**
     * Read a guide, relative to the package root.
     *
     * @param  string  $file
     * @return string
     */
    private function contents(string $file): string
    {
        return (string) file_get_contents(self::root() . '/' . $file);
    }

    /**
     * Read a Markdown file without its fenced code blocks, whose lines are
     * neither links nor headings.
     *
     * @param  string  $file
     * @return string
     */
    private function prose(string $file): string
    {
        return (string) preg_replace('/^(\s*)(`{3,}|~{3,}).*?^\1\2\s*$/ms', '', $this->contents($file));
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
