<?php

declare(strict_types = 1);

namespace Tests\Feature\Docs;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Iam\Authorization\AccessMandates;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use Tests\TestCase;

/**
 * The bindings guide documents every seam binding the package declares
 * (IAM-12.3): each row of every capability's `*Seams` table appears in one of
 * the guide's binding tables, once, with the adapter it is bound to, the
 * member's defaults it replaces, and whether `iam:check` holds it mandatory.
 *
 * A binding table is a Markdown table whose header starts with `Contract`. Its
 * columns are the contract, what it is bound to, what it replaces (`None` for a
 * seam no member binds), whether it is mandatory and what replacing it risks.
 * Classes are named in backticks, relative to `SineMacula\Laravel\`, as the
 * guide says. A seam is mandatory `Always` when `iam:check` holds it so under
 * any configuration, `While ...` when only some configuration makes it so, and
 * `No` otherwise; the configurations compared are the tests' own, under which
 * no conditional mandate holds, and one under which every conditional mandate
 * does (SSO's enforcement and a protocol on, a tenant tree and a tenant MFA
 * requirement named). Every row of a binding table must be one of the seams, so
 * a seam that is gone cannot stay documented.
 *
 * Everything else the provider binds or registers is documented in the table of
 * other bindings: the container keys an application with the package holds and
 * one with the members alone does not (each scoped record under its own name),
 * the seams aside, and the contributors it registers with the members, so a
 * binding added later cannot be left out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class BindingsGuideTest extends TestCase
{
    /** @var string The guide, from the package root. */
    private const string GUIDE = 'docs/guides/bindings.md';

    /** @var string The namespace every class in the guide is named relative to. */
    private const string ROOT_NAMESPACE = 'SineMacula\Laravel\\';

    /** @var string The heading of a binding table's first column. */
    private const string CONTRACT_COLUMN = 'Contract';

    /** @var string What the guide says of a seam no member binds a default to. */
    private const string NO_DEFAULT = 'None';

    /** @var string What the guide says of a seam only some configuration makes mandatory, followed by that configuration. */
    private const string CONDITIONAL_MANDATE = 'While ...';

    /** @var int The column holding the adapter. */
    private const int ADAPTER = 1;

    /** @var int The column holding the member's defaults. */
    private const int DEFAULTS = 2;

    /** @var int The column holding whether the seam is mandatory. */
    private const int MANDATORY = 3;

    /** @var int The columns a binding table holds. */
    private const int COLUMNS = 5;

    /** @var list<string> The keys of `laravel-authorization`'s configuration that name a class its rows keep, as the authorization guide lists them. */
    private const array AUTHORIZATION_KEYS = [
        '`authorization.subject_resolver`',
        '`authorization.requirement_checker`',
        '`authorization.session.source`',
        '`authorization.identity_directory`',
        '`authorization.tenant_tree`',
    ];

    /** @var string The heading of the first column of the table of the package's other bindings. */
    private const string BINDING_COLUMN = 'Binding';

    /** @var string The heading of the column saying what replacing a binding risks. */
    private const string REPLACING_COLUMN = 'Replacing it';

    /** @var string What a row says of a binding that is not the application's to replace. */
    private const string NOT_YOURS = 'Do not replace';

    /** @var list<string> The other bindings whose replacement the package keeps, so their rows must say what it risks. */
    private const array KEPT = [
        '`Iam\Tenancy\Contracts\GrantScope`',
        'The `sso` context namespace',
        '`Iam\Audit\CallerContextContributor`, audit-log\'s context contributor',
    ];

    /** @var string How the table of other bindings names a context namespace the package registers with `laravel-authentication`. */
    private const string CONTEXT_NAMESPACE = 'The `%s` context namespace';

    /**
     * Every seam binding is documented, once, with its adapter, its defaults
     * and its mandate, and nothing else is documented as one.
     *
     * @return void
     */
    public function testEverySeamBindingIsDocumentedWithItsAdapter(): void
    {
        $guide = self::guide();
        $seams = $this->seams();

        self::assertNotEmpty($seams);
        self::assertSame([], self::problems($guide, $seams));
    }

    /**
     * Every capability the package binds through is documented, so a capability
     * added to the service provider cannot be left out.
     *
     * @return void
     */
    public function testEveryCapabilityHasRows(): void
    {
        foreach (IamServiceProvider::seamProviders() as $provider) {
            self::assertNotEmpty($this->capability($provider)->seams($this->app?->make('config') ?? self::fail('No configuration.')), $provider);
        }
    }

    /**
     * A seam whose row is missing from the guide is reported by its contract.
     *
     * @return void
     */
    public function testAMissingRowIsReported(): void
    {
        $guide = self::withoutRow(self::guide(), 'Mfa\Contracts\SessionRevoker');

        self::assertContains('`Mfa\Contracts\SessionRevoker` is not documented.', self::problems($guide, $this->seams()));
    }

    /**
     * A row naming another adapter than the seam is bound to is reported.
     *
     * @return void
     */
    public function testARowWithAnotherAdapterIsReported(): void
    {
        $guide = str_replace('`Iam\Mfa\SessionRevokerAdapter`', '`Iam\Mfa\StepUpAdapter`', self::guide());

        self::assertContains('`Mfa\Contracts\SessionRevoker` does not name its adapter `Iam\Mfa\SessionRevokerAdapter`.', self::problems($guide, $this->seams()));
    }

    /**
     * A row that leaves out a default the adapter replaces is reported.
     *
     * @return void
     */
    public function testARowMissingADefaultIsReported(): void
    {
        $guide = str_replace('`Mfa\Proofs\GenerationSessionRevoker`', 'MFA\'s revoker', self::guide());

        self::assertContains('`Mfa\Contracts\SessionRevoker` does not name the default `Mfa\Proofs\GenerationSessionRevoker` it replaces.', self::problems($guide, $this->seams()));
    }

    /**
     * A mandatory seam documented as optional, or an optional one documented as
     * mandatory, is reported.
     *
     * @return void
     */
    public function testAWrongMandateIsReported(): void
    {
        $seams = $this->seams();
        $guide = self::guide();

        $wrong = [
            'Mfa\Contracts\SessionRevoker'       => ['No', 'Always'],
            'Sso\Contracts\SessionRevocation'    => ['While SSO is in use', 'Always'],
            'Mfa\Contracts\ActiveTenantResolver' => ['Always', 'While ...'],
            'Mfa\Contracts\StepUp'               => ['Always', 'No'],
        ];

        foreach ($wrong as $contract => [$documented, $mandate]) {
            $problem = sprintf('`%s` must say it is mandatory `%s`.', $contract, $mandate);

            self::assertContains($problem, self::problems(self::withMandate($guide, $contract, $documented), $seams));
        }
    }

    /**
     * A mandate cell that only begins with the mandate, or a conditional one
     * that names no condition, is reported, so `Always optional`, `Nobody` and
     * a bare `While` cannot pass for `Always`, `No` and `While ...`.
     *
     * @return void
     */
    public function testAMandateThatOnlyBeginsWithTheWordIsReported(): void
    {
        $seams = $this->seams();
        $guide = self::guide();

        $loose = [
            'Mfa\Contracts\SessionRevoker'       => ['Always optional', 'Always'],
            'Mfa\Contracts\StepUp'               => ['Nobody', 'No'],
            'Mfa\Contracts\ActiveTenantResolver' => ['While ', 'While ...'],
        ];

        foreach ($loose as $contract => [$documented, $mandate]) {
            $problem = sprintf('`%s` must say it is mandatory `%s`.', $contract, $mandate);

            self::assertContains($problem, self::problems(self::withMandate($guide, $contract, $documented), $seams));
        }
    }

    /**
     * A row no seam answers, and a seam documented twice, are reported.
     *
     * @return void
     */
    public function testAStaleOrRepeatedRowIsReported(): void
    {
        $seams = $this->seams();
        $guide = self::guide();
        $row   = self::rowOf($guide, 'Mfa\Contracts\StepUp');

        $stale    = str_replace($row, str_replace('`Mfa\Contracts\StepUp`', '`Mfa\Contracts\Retired`', $row), $guide);
        $repeated = str_replace($row, $row . "\n" . $row, $guide);

        self::assertContains('`Mfa\Contracts\Retired` is documented as a binding, but no seam binds it.', self::problems($stale, $seams));
        self::assertContains('`Mfa\Contracts\StepUp` is documented 2 times.', self::problems($repeated, $seams));
    }

    /**
     * A binding table row with too few columns is reported, so a cell cannot go
     * missing unnoticed.
     *
     * @return void
     */
    public function testARowWithTooFewColumnsIsReported(): void
    {
        $guide = self::guide();
        $row   = self::rowOf($guide, 'Mfa\Contracts\StepUp');
        $cells = explode('|', $row);
        $short = implode('|', array_slice($cells, 0, 4)) . '|';

        self::assertContains('`Mfa\Contracts\StepUp` has 3 columns, not 5.', self::problems(str_replace($row, $short, $guide), $seams = $this->seams()));
        self::assertNotEmpty($seams);
    }

    /**
     * Every row of the table of the package's other bindings says whether the
     * binding may be replaced (IAM-12.3), and every binding whose replacement
     * the package keeps (the grant scope and the `sso` context contributor)
     * says what replacing it risks rather than only that it is not the
     * application's to replace.
     *
     * @return void
     */
    public function testEveryOtherBindingSaysWhatReplacingItRisks(): void
    {
        self::assertSame([], self::otherBindingProblems(self::guide()));
    }

    /**
     * The authorization section's introduction names every key of
     * `laravel-authorization`'s configuration a row keeps a class in, as the
     * authorization guide does, and says the grant hooks are listed, not named
     * as a class.
     *
     * @return void
     */
    public function testTheAuthorizationIntroductionNamesEveryKeptKey(): void
    {
        $guide         = self::guide();
        $start         = strpos($guide, "\n## Authorization\n");
        $introduction  = $start === false ? '' : substr($guide, $start, (int) strpos($guide, "\n| ", $start) - $start);
        $flat          = (string) preg_replace('/\s+/', ' ', $introduction);
        $authorization = (string) preg_replace('/\s+/', ' ', (string) file_get_contents(dirname(__DIR__, 3) . '/docs/guides/authorization.md'));

        foreach (self::AUTHORIZATION_KEYS as $key) {
            self::assertStringContainsString($key, $flat);
            self::assertStringContainsString($key, $authorization);
        }

        self::assertStringContainsString('listed in `authorization.grant_hooks`, not named as a class', $flat);
    }

    /**
     * A row of the other bindings that says nothing of replacing it, a kept
     * binding that only says it is not to be replaced, and a table with no
     * column for it are reported.
     *
     * @return void
     */
    public function testAnOtherBindingSilentOnReplacingItIsReported(): void
    {
        $guide = self::guide();
        $row   = self::rowOf($guide, 'Iam\Audit\JobCallers');
        $kept  = self::rowOf($guide, 'Iam\Tenancy\Contracts\GrantScope');
        $cells = self::cells($kept);

        $cells[4] = 'Do not replace it.';

        $silent   = str_replace($row, implode('|', array_slice(explode('|', $row), 0, 5)) . '|', $guide);
        $unwarned = str_replace($kept, '| ' . implode(' | ', $cells) . ' |', $guide);
        $headless = (string) preg_replace('/^\| Binding (.*)\| Replacing it\s*\|$/m', '| Binding $1|', $guide);

        self::assertSame(['`Iam\Audit\JobCallers` does not say whether replacing it is safe.'], self::otherBindingProblems($silent));
        self::assertSame(['`Iam\Tenancy\Contracts\GrantScope` is kept when replaced, but does not say what replacing it risks.'], self::otherBindingProblems($unwarned));
        self::assertSame(['The table of other bindings has no `Replacing it` column.'], self::otherBindingProblems($headless));
        self::assertSame(['The guide has no table of other bindings.'], self::otherBindingProblems('# Bindings'));
    }

    /**
     * Everything the provider binds or registers that is not a seam is a row of
     * the table of other bindings (IAM-12.3): each container key an application
     * with the package holds and one with the members alone does not, and each
     * contributor it registers with the members.
     *
     * @return void
     */
    public function testEveryOtherBindingOfTheProviderIsDocumented(): void
    {
        $this->reorderProviders(self::MEMBER_PROVIDERS);

        $members = $this->registrations();

        $this->reorderProviders([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);

        $made = array_diff_key($this->registrations(), $members, $this->seams());

        self::assertArrayHasKey('Iam\Bindings\BindingOutcome', $made);
        self::assertArrayHasKey('iam.audit.registered', $made);
        self::assertArrayHasKey('Iam\Audit\CallerContextContributor', $made);
        self::assertArrayHasKey(sprintf(self::CONTEXT_NAMESPACE, 'sso'), $made);
        self::assertSame([], self::undocumented(self::guide(), $made));
    }

    /**
     * A binding or registration of the provider's with no row in the table of
     * other bindings is reported by its name.
     *
     * @return void
     */
    public function testAnUndocumentedOtherBindingIsReported(): void
    {
        $made = [
            'Iam\Bindings\BindingOutcome'        => ['`Iam\Bindings\BindingOutcome`'],
            'iam.audit.registered'               => ['`iam.audit.registered`', '`\'iam.audit.registered\'`'],
            'Iam\Audit\CallerContextContributor' => ['`Iam\Audit\CallerContextContributor`'],
        ];

        $guide = self::withoutRow(self::guide(), 'Iam\Bindings\BindingOutcome');

        self::assertSame([], self::undocumented(self::guide(), $made));
        self::assertSame(['Iam\Bindings\BindingOutcome'], self::undocumented($guide, $made));
        self::assertSame(array_keys($made), self::undocumented('# Bindings', $made));
    }

    /**
     * What the application's container holds and the members hold registered,
     * each keyed by its name and listing how the table of other bindings may
     * name it: every container key, a key scoped under this package's prefix
     * by the name it is scoped for, a class relative to the root namespace;
     * every contributor audit-log runs; and every namespace of
     * `laravel-authentication`'s authentication context.
     *
     * @return array<string, list<string>>
     */
    private function registrations(): array
    {
        $app = $this->app ?? self::fail('No application.');

        $keys = [
            ...array_keys($app->getBindings()),
            ...array_keys(self::containerProperty($app, 'instances')),
            ...array_keys(self::containerProperty($app, 'aliases')),
            ...$app->make(ContributorRegistry::class)->classes(),
        ];

        $registrations = [];

        foreach (array_map(strval(...), $keys) as $key) {

            $name = self::relative(str_starts_with($key, BindingRule::SCOPED_PREFIX) ? substr($key, strlen(BindingRule::SCOPED_PREFIX)) : $key);

            $registrations[$name] = ['`' . $name . '`', '`\'' . $name . '\'`'];
        }

        foreach (array_keys($app->make(ContextContributors::class)->registered()) as $namespace) {
            $registrations[sprintf(self::CONTEXT_NAMESPACE, $namespace)] = [sprintf(self::CONTEXT_NAMESPACE, $namespace)];
        }

        return $registrations;
    }

    /**
     * One of the container's own keyed lists, which it keeps protected.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $property
     * @return array<array-key, mixed>
     */
    private static function containerProperty(Container $container, string $property): array
    {
        $value = (new \ReflectionProperty(Container::class, $property))->getValue($container);

        return is_array($value) ? $value : self::fail(sprintf('The container holds no %s.', $property));
    }

    /**
     * The bindings and registrations no first cell of the table of other
     * bindings names, in any way the table may name it.
     *
     * @param  string  $guide
     * @param  array<string, list<string>>  $made
     * @return list<string>
     */
    private static function undocumented(string $guide, array $made): array
    {
        $names = implode("\n", array_map(static fn (array $cells): string => $cells[0] ?? '', self::otherBindingTable($guide)[1] ?? []));

        $missing = array_filter($made, static function (array $spellings) use ($names): bool {

            foreach ($spellings as $spelling) {
                if (str_contains($names, $spelling)) {
                    return false;
                }
            }

            return true;
        });

        return array_map(strval(...), array_keys($missing));
    }

    /**
     * Every seam binding, keyed by its contract relative to the root namespace,
     * with whether it is mandatory under the tests' configuration and under one
     * in which every conditional mandate holds, each base mandate read before
     * the configuration changes, since a row may ask its mandate only as it is
     * read.
     *
     * @return array<string, array{seam: \SineMacula\Laravel\Iam\Bindings\SeamBinding, base: bool, full: bool}>
     */
    private function seams(): array
    {
        $config = $this->app?->make('config') ?? self::fail('No configuration.');
        $base   = array_map(static fn (SeamBinding $seam): bool => $seam->isMandatory(), $this->bindings($config));

        $config->set('sso.features.enforcement', true);
        $config->set('sso.features.saml2', true);
        $config->set('sso.features.domain_linking', true);
        $config->set('iam.tenancy.tree', FakeTenantTree::class);
        $config->set('iam.tenancy.mfa_requirement', FakeTenantMfaRequirement::class);
        $config->set('auth.guards.keys', ['driver' => 'api_key', 'application' => ['methods' => ['api_key']]]);
        $config->set(AccessMandates::APPLICATION_ACCESS, ['api' => 'api:use']);

        $seams = [];

        foreach ($this->bindings($config) as $abstract => $seam) {
            $seams[$abstract] = ['seam' => $seam, 'base' => $base[$abstract] ?? false, 'full' => $seam->isMandatory()];
        }

        return $seams;
    }

    /**
     * Every capability's seam bindings under the configuration, keyed by the
     * contract relative to the root namespace.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return array<string, \SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    private function bindings(Repository $config): array
    {
        $bindings = [];

        foreach (IamServiceProvider::seamProviders() as $provider) {
            foreach ($this->capability($provider)->seams($config) as $seam) {
                $bindings[self::relative($seam->abstract)] = $seam;
            }
        }

        return $bindings;
    }

    /**
     * The capability the provider names, resolved from the container.
     *
     * @param  class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>  $provider
     * @return \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams
     */
    private function capability(string $provider): ProvidesSeams
    {
        $capability = $this->app?->make($provider);

        self::assertInstanceOf(ProvidesSeams::class, $capability);

        return $capability;
    }

    /**
     * What the guide gets wrong about the seams, in the order found.
     *
     * @param  string  $guide
     * @param  array<string, array{seam: \SineMacula\Laravel\Iam\Bindings\SeamBinding, base: bool, full: bool}>  $seams
     * @return list<string>
     */
    private static function problems(string $guide, array $seams): array
    {
        $rows     = self::bindingRows($guide);
        $problems = [];

        foreach ($rows as $contract => $found) {
            if (!isset($seams[$contract])) {
                $problems[] = sprintf('`%s` is documented as a binding, but no seam binds it.', $contract);
            }

            if (count($found) <= 1) {
                continue;
            }

            $problems[] = sprintf('`%s` is documented %d times.', $contract, count($found));
        }

        foreach ($seams as $contract => $seam) {
            $cells = $rows[$contract][0] ?? null;

            if ($cells === null) {
                $problems[] = sprintf('`%s` is not documented.', $contract);

                continue;
            }

            array_push($problems, ...self::rowProblems($contract, $cells, $seam['seam'], self::mandate($seam['base'], $seam['full'])));
        }

        return $problems;
    }

    /**
     * What one row gets wrong about its seam.
     *
     * @param  string  $contract
     * @param  list<string>  $cells
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $seam
     * @param  string  $mandate
     * @return list<string>
     */
    private static function rowProblems(string $contract, array $cells, SeamBinding $seam, string $mandate): array
    {
        if (count($cells) !== self::COLUMNS) {
            return [sprintf('`%s` has %d columns, not %d.', $contract, count($cells), self::COLUMNS)];
        }

        $problems = [];
        $adapter  = self::relative($seam->adapter);

        if (!str_contains($cells[self::ADAPTER], '`' . $adapter . '`')) {
            $problems[] = sprintf('`%s` does not name its adapter `%s`.', $contract, $adapter);
        }

        foreach ($seam->memberDefaults as $default) {
            if (str_contains($cells[self::DEFAULTS], '`' . self::relative($default) . '`')) {
                continue;
            }

            $problems[] = sprintf('`%s` does not name the default `%s` it replaces.', $contract, self::relative($default));
        }

        if ($seam->memberDefaults === [] && !str_starts_with($cells[self::DEFAULTS], self::NO_DEFAULT)) {
            $problems[] = sprintf('`%s` must say it replaces `%s`.', $contract, self::NO_DEFAULT);
        }

        if (!self::saysMandate($cells[self::MANDATORY], $mandate)) {
            $problems[] = sprintf('`%s` must say it is mandatory `%s`.', $contract, $mandate);
        }

        return $problems;
    }

    /**
     * Whether the cell says exactly the mandate: `Always` and `No` alone, and
     * `While ...` as `While ` and the condition that makes the seam mandatory,
     * so a cell such as `Always optional`, `Nobody` or a bare `While` is not
     * read as a mandate.
     *
     * @param  string  $cell
     * @param  string  $mandate
     * @return bool
     */
    private static function saysMandate(string $cell, string $mandate): bool
    {
        if ($mandate !== self::CONDITIONAL_MANDATE) {
            return $cell === $mandate;
        }

        $prefix = rtrim(self::CONDITIONAL_MANDATE, '.');

        return str_starts_with($cell, $prefix) && trim(substr($cell, strlen($prefix))) !== '';
    }

    /**
     * What the guide must say of a seam's mandate.
     *
     * @param  bool  $base
     * @param  bool  $full
     * @return string
     */
    private static function mandate(bool $base, bool $full): string
    {
        return match (true) {
            $base && $full => 'Always',
            $full          => self::CONDITIONAL_MANDATE,
            default        => 'No',
        };
    }

    /**
     * The cells of every row of every binding table in the guide, keyed by the
     * contract its first cell names, each list in the order found.
     *
     * @param  string  $guide
     * @return array<string, list<list<string>>>
     */
    private static function bindingRows(string $guide): array
    {
        $rows    = [];
        $inTable = false;

        foreach (preg_split('/\R/', $guide) ?: [] as $line) {
            if (!str_starts_with($line, '|')) {
                $inTable = false;

                continue;
            }

            $cells = self::cells($line);

            if (($cells[0] ?? null) === self::CONTRACT_COLUMN) {
                $inTable = true;

                continue;
            }

            if (!$inTable || preg_match('/^`([^`]+)`$/', $cells[0] ?? '', $match) !== 1) {
                continue;
            }

            $rows[$match[1]][] = $cells;
        }

        return $rows;
    }

    /**
     * What the table of the package's other bindings leaves unsaid about
     * replacing them: no column for it, a row with nothing in it, and a binding
     * whose replacement the package keeps saying only that it is not to be
     * replaced.
     *
     * @param  string  $guide
     * @return list<string>
     */
    private static function otherBindingProblems(string $guide): array
    {
        $table = self::otherBindingTable($guide);

        if ($table === null) {
            return ['The guide has no table of other bindings.'];
        }

        [$header, $rows] = $table;

        if (($header[self::COLUMNS - 1] ?? null) !== self::REPLACING_COLUMN) {
            return [sprintf('The table of other bindings has no `%s` column.', self::REPLACING_COLUMN)];
        }

        $problems = [];

        foreach ($rows as $cells) {
            $replacing = $cells[self::COLUMNS - 1] ?? '';

            $problem = match (true) {
                $replacing === ''                                                                     => '%s does not say whether replacing it is safe.',
                in_array($cells[0], self::KEPT, true) && str_starts_with($replacing, self::NOT_YOURS) => '%s is kept when replaced, but does not say what replacing it risks.',
                default                                                                               => null,
            };

            if ($problem === null) {
                continue;
            }

            $problems[] = sprintf($problem, $cells[0]);
        }

        return $problems;
    }

    /**
     * The header and the rows of the table of the package's other bindings, the
     * table whose first column is `Binding`, or nothing when the guide has no
     * such table.
     *
     * @param  string  $guide
     * @return ?array{0: list<string>, 1: list<list<string>>}
     */
    private static function otherBindingTable(string $guide): ?array
    {
        $lines = preg_split('/\R/', $guide) ?: [];
        $start = null;

        foreach ($lines as $index => $line) {
            if (str_starts_with($line, '|') && (self::cells($line)[0] ?? null) === self::BINDING_COLUMN) {
                $start = $index;

                break;
            }
        }

        if ($start === null) {
            return null;
        }

        $rows = [];

        for ($index = $start + 2; isset($lines[$index]) && str_starts_with($lines[$index], '|'); $index++) {
            $rows[] = self::cells($lines[$index]);
        }

        return [self::cells($lines[$start]), $rows];
    }

    /**
     * The trimmed cells of a table row.
     *
     * @param  string  $line
     * @return list<string>
     */
    private static function cells(string $line): array
    {
        return array_map(trim(...), explode('|', trim(trim($line), '|')));
    }

    /**
     * The row of the guide whose contract is the one given.
     *
     * @param  string  $guide
     * @param  string  $contract
     * @return string
     */
    private static function rowOf(string $guide, string $contract): string
    {
        foreach (preg_split('/\R/', $guide) ?: [] as $line) {
            if (str_starts_with($line, '| `' . $contract . '`')) {
                return $line;
            }
        }

        self::fail(sprintf('The guide has no row for %s.', $contract));
    }

    /**
     * The guide with the row of the contract taken out.
     *
     * @param  string  $guide
     * @param  string  $contract
     * @return string
     */
    private static function withoutRow(string $guide, string $contract): string
    {
        return str_replace(self::rowOf($guide, $contract) . "\n", '', $guide);
    }

    /**
     * The guide with the mandate of the contract's row replaced.
     *
     * @param  string  $guide
     * @param  string  $contract
     * @param  string  $mandate
     * @return string
     */
    private static function withMandate(string $guide, string $contract, string $mandate): string
    {
        $row   = self::rowOf($guide, $contract);
        $cells = self::cells($row);

        $cells[self::MANDATORY] = $mandate;

        return str_replace($row, '| ' . implode(' | ', $cells) . ' |', $guide);
    }

    /**
     * The class named relative to the root namespace, as the guide names it.
     *
     * @param  string  $class
     * @return string
     */
    private static function relative(string $class): string
    {
        return str_starts_with($class, self::ROOT_NAMESPACE) ? substr($class, strlen(self::ROOT_NAMESPACE)) : $class;
    }

    /**
     * The guide's text.
     *
     * @return string
     */
    private static function guide(): string
    {
        $guide = file_get_contents(dirname(__DIR__, 3) . '/' . self::GUIDE);

        return $guide === false ? self::fail('The bindings guide is missing.') : $guide;
    }
}
