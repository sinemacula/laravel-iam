<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for what the guides, and the configuration file's own comments,
 * say about behaviour a reader acts on: the example controllers answer every
 * refusal a redemption throws, the caller is named to SSO as the redemption
 * names it, every `Iam::callers()->run()` is handed the caller, and the
 * statements of the code's behaviour a reader relies on for security (what the
 * evidence gates count, what `laravel-authorization`'s defaults leave open,
 * what `iam:check` can find and reads, what rotating `APP_KEY` restarts or
 * ends, which keys sign a guard's tokens, which queue workers deliver what,
 * which jobs the worker reset skips and what it keeps, what replacing a binding
 * the package keeps risks, what moving onto the package replaces and in which
 * order, what the members' test fakes replace, which callers SSO's freshness
 * judges, how the audit trail names a tenant, and when a tenant resolver is
 * owed) say what the code does.
 *
 * A guide is prose, so these hold the sentences that state each behaviour, and
 * the code the sentences describe is held by its own tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class GuideStatementsTest extends TestCase
{
    /** @var string The example application's guide, whose controllers a reader copies. */
    private const string EXAMPLE = 'docs/guides/example-application.md';

    /** @var string The pattern of a fenced PHP block. */
    private const string PHP_BLOCK = '/```php\n(.*?)```/s';

    /** @var string The pattern of a call that runs work for a caller, and its first argument. */
    private const string CALLER_RUN = '/Iam::callers\(\)->run\(\s*(\$\w+)/';

    /**
     * Rows of a redemption, and the exception it throws for a refusal by
     * `laravel-authentication`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRedemptions(): iterable
    {
        yield 'a sign-in' => ['Iam::signIns()->redeem(', 'ExternalSignInRefusedException'];

        yield 'a re-authentication' => ['Iam::reauthentications()->redeem(', 'ExternalReauthenticationRefusedException'];
    }

    /**
     * Every example controller that redeems a code catches the exception the
     * redemption throws when `laravel-authentication` refuses, so a copied
     * controller answers the refusal rather than a server error.
     *
     * @param  string  $call
     * @param  string  $exception
     * @return void
     */
    #[DataProvider('provideRedemptions')]
    public function testEveryExampleRedemptionCatchesItsRefusal(string $call, string $exception): void
    {
        $blocks = array_filter(self::phpBlocks(self::EXAMPLE), static fn (string $block): bool => str_contains($block, $call));

        self::assertNotSame([], $blocks, sprintf('The example application makes no %s call.', $call));

        foreach ($blocks as $block) {
            self::assertStringContainsString(sprintf('catch (%s $', $exception), $block, sprintf('An example that calls %s does not catch %s.', $call, $exception));
        }
    }

    /**
     * The example names the caller to SSO by the identity's primary key, as the
     * redemption names it, never by its auth identifier, which a model may keep
     * in another column.
     *
     * @return void
     */
    public function testTheExampleNamesTheCallerToSsoByItsKey(): void
    {
        $contents = self::contents(self::EXAMPLE);

        self::assertStringNotContainsString('getAuthIdentifier()', $contents);
        self::assertStringContainsString('new IdentityReference($caller->identity->getMorphClass(), (string) $caller->identity->getKey())', $contents);
    }

    /**
     * Every `Iam::callers()->run()` the guides and the configuration file show
     * is handed the caller, as the method takes it.
     *
     * @return void
     */
    public function testEveryCallerScopeIsHandedTheCaller(): void
    {
        $arguments = [];

        foreach ([...self::guides(), 'config/iam.php'] as $file) {

            preg_match_all(self::CALLER_RUN, self::contents($file), $matches);

            foreach ($matches[1] as $argument) {
                $arguments[$file . ': ' . $argument] = $argument;
            }
        }

        self::assertArrayHasKey('config/iam.php: $caller', $arguments);
        self::assertSame([], array_keys(array_filter($arguments, static fn (string $argument): bool => $argument !== '$caller')));
    }

    /**
     * Rows of a guide, a statement it must make of the code's behaviour, and
     * one it must not, since the code does otherwise.
     *
     * @return iterable<string, array{0: string, 1: list<string>, 2: list<string>}>
     */
    public static function provideStatements(): iterable
    {
        yield 'a tenant a person may not act in fails the sign-in' => [
            'docs/guides/testing.md',
            ['`The caller did not sign in on guard [api]: [tenant_ineligible].`'],
            ['one the resolver does not find throws'],
        ];

        yield 'no level is verified through SSO under MFA\'s default' => [
            'docs/guides/testing.md',
            ['`$verified` can reach none of AAL1, AAL2 or AAL3'],
            ['an SSO session verified with an authenticator app reaches AAL1, so a'],
        ];

        yield 'trusting a connection does not go around SSO\'s evidence gate' => [
            'docs/guides/mfa-and-sso.md',
            ['Trusting the connection in the combination policy does not go around the first gate.', '`laravel-authentication`\'s requirement check never sees the connection'],
            [],
        ];

        yield 'SSO\'s tasks take a mutex while its switch is on' => [
            'docs/guides/operations.md',
            ['`sso.operations.cache_mutexes`', '`sso.operations.mutex_minutes`'],
            ['No task takes a cache mutex'],
        ];

        yield 'rotating APP_KEY restarts MFA\'s send caps' => [
            'docs/guides/operations.md',
            ['throttles and send caps start afresh, lockouts are kept'],
            ['outstanding codes stop working; throttles start afresh, lockouts are kept'],
        ];

        yield 'rotating APP_KEY ends password reset links when the code key is derived' => [
            'docs/guides/operations.md',
            [
                'signed links (an identifier verification, an identifier change), signed',
                'the code key, when `authentication.codes.key` is unset: one-time codes, password reset links and delivery windows',
                'outstanding codes and password reset links stop working at once: the code key reads no previous key',
                'every queued delivery (codes, password resets, identifier change codes and notices), encrypted',
            ],
            ['a password reset, a verification', 'queued code deliveries'],
        ];

        yield 'rotating the code key restarts every destination\'s delivery caps' => [
            'docs/guides/operations.md',
            [
                'It also restarts every destination\'s delivery window',
                '`authentication.codes.max_deliveries` cap and `authentication.codes.resend_cooldown_seconds` cooldown start again, for every code it issues',
                'every destination\'s delivery cap and resend cooldown restart',
                'Rotating an explicit `authentication.codes.key` restarts the delivery caps and cooldowns the same way',
                'Do not rotate either key during an attack on those limits',
            ],
            ['invalidates only the codes and reset links outstanding', 'Do not rotate during an attack on those limits'],
        ];

        yield 'the outbox is drained by the scheduler, not a queue worker' => [
            'docs/guides/operations.md',
            ['Audit-log\'s outbox uses no queue.', 'So Laravel\'s scheduler must run', 'a queue worker drains nothing'],
            ['audit-log\'s outbox, when its delivery is through the outbox'],
        ];

        yield 'iam:check refuses an alert listener class that cannot be handed the event, and builds nothing' => [
            'docs/guides/checks.md',
            ['or a listener class with neither `handle()` nor `__invoke()`', 'The check builds nothing, so a name you bound in the container yourself passes it'],
            ['or a listener with neither `handle()` nor `__invoke()`'],
        ];

        yield 'an exemption change is reported as the tenant policy describes' => [
            'docs/guides/configuration.md',
            ['every exemption your `EnforcementExemption` grants or withdraws ([Authentication and SSO](authentication-and-sso.md#the-tenant-policy))'],
            ['as [Provisioning and tenancy](provisioning-and-tenancy.md) describes'],
        ];

        yield 'provisioning and tenancy points an exemption change at the same report' => [
            'docs/guides/provisioning-and-tenancy.md',
            ['is owed whenever your `EnforcementExemption` grants or withdraws an identity\'s exemption'],
            [],
        ];

        yield 'a lock wait timeout is retried, as the operations guide says' => [
            'docs/guides/configuration.md',
            ['deadlocks, meets a lock wait timeout or finds SSO\'s link candidates changed'],
            ['(SQLSTATE 40001), deadlocks or finds SSO\'s link candidates changed'],
        ];

        yield 'a person who already holds a factor can be acted as, again and again' => [
            'docs/guides/testing.md',
            [
                '### A person who already holds a factor',
                'The helper completes the sign-in as the person would, by verifying a factor',
                'So the same person can be acted as again, verified again, in another tenant or at another level',
                '`The caller did not sign in on guard [api]: [pending: mfa]. A started session holds no first factor MFA can judge, ...`',
            ],
            ['act as a person who holds none, and let `$verified` enrol one'],
        ];

        yield 'iam:check refuses an MFA application on a guard of another driver' => [
            'docs/guides/checks.md',
            ['*`mfa.applications.<name>` names a guard in `auth.guards` whose driver is not `jwt`: MFA\'s application is a guard that holds sessions.*'],
            [],
        ];

        yield 'the MFA guide says which MFA applications iam:check reports' => [
            'docs/guides/authentication-and-mfa.md',
            ['an MFA application that names no guard, and one whose guard is of another driver'],
            [],
        ];

        yield 'only this package\'s checks keep off the database, and none prints a secret' => [
            'docs/guides/checks.md',
            [
                'Each of this package\'s checks reads configuration and the container only',
                'audit-log\'s reads the schema of its tables, so `iam:check` needs the database, after `migrate`',
                'never a secret or credential',
            ],
            ['Every check reads configuration and the container only', 'never a configured value'],
        ];

        yield 'the design note says the same of the checks' => [
            'docs/design/install-and-check.md',
            ['Each of this package\'s checks reads configuration and the container only', 'never a secret or credential'],
            ['never a configured value'],
        ];

        yield 'audit-log\'s prune is noted on its own terms' => [
            'docs/guides/checks.md',
            [
                '`audit-log:seal --sweep` and `audit-log:verify`): turn',
                'though its retention can delete entries.*: shown only while audit-log\'s retention can delete entries',
                '*audit-log cannot judge whether its retention can delete entries (...), and no event on the schedule runs `audit-log:prune`; ...*',
            ],
            ['`audit-log:verify` and `audit-log:prune`): turn'],
        ];

        yield 'moving onto the package replaces the SSO redemption controllers' => [
            'docs/guides/installation.md',
            [
                'Replace your own redemption of SSO\'s handoff codes.',
                '`SineMacula\Laravel\Sso\Handoffs\HandoffRedemption` (`admit()` or `redeem()`)',
                'Replace every such controller with `Iam::signIns()->redeem()`, `Iam::reauthentications()->redeem()` and `Iam::links()->redeem()`',
            ],
            [],
        ];

        yield 'neither member\'s fake sender is used beside the gateway fakes' => [
            'docs/guides/testing.md',
            ['`SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender`', 'both members\' codes, MFA\'s email and SMS codes among them, stop reaching it'],
            [],
        ];

        yield 'each kit\'s checks can be called directly' => [
            'docs/guides/testing.md',
            ['Each kit\'s checks are static assertions on the `Seams\*Contract` class beside its trait', '`Seams\MembershipsContract::assertNeverCompleteWhenUnreadable()`'],
            [],
        ];

        yield 'a grant scope of the application\'s own is warned against' => [
            'docs/guides/bindings.md',
            [
                'Yours is kept, but leave it on `Iam\Tenancy\UnknownGrantScope` until `laravel-authorization`\'s grant scope query is bound.',
                'lets that tenant\'s verified domain link the person, so its provider can sign in as them',
                'and takes this one out of SSO\'s boot',
            ],
            ['None of them is yours to replace'],
        ];

        yield 'iam:check cannot find a binding made in the application\'s providers' => [
            'docs/guides/installation.md',
            ['replaces the adapter silently, and is checked only if the seam is mandatory'],
            ['`iam:check` notes each seam it kept with'],
        ];

        yield 'authorization decides with no tenant, and isolates none' => [
            'docs/guides/authorization.md',
            ['`laravel-authorization` decides with **no active tenant**', '`SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant`'],
            [],
        ];

        yield 'what waits on laravel-authorization, and what it leaves to you' => [
            'docs/guides/authorization.md',
            [
                '`SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy`',
                '`Iam::scopeWidenings()->widen()`',
                'Check every SSO, MFA and audit-log administrative call yourself',
                '`SineMacula\Laravel\AuditLog\Access\DenyAllPolicy`',
            ],
            [],
        ];

        yield 'the example warns that authorize: isolates no tenant' => [
            self::EXAMPLE,
            ['**No tenant isolation from `authorize:` or `permission:` yet.**'],
            [],
        ];

        yield 'nobody can read the audit trail yet' => [
            'docs/guides/audit-trail.md',
            ['`SineMacula\Laravel\AuditLog\Access\DenyAllPolicy`'],
            [],
        ];

        yield 'the seams still to come include the refusing defaults' => [
            'docs/guides/bindings.md',
            ['`Authorization\Contracts\SessionPolicySource`', '`AuditLog\Contracts\AuditAccessPolicy`', '`Sso\Contracts\LinkConfirmation`'],
            [],
        ];

        yield 'the application\'s own audit codes need definitions' => [
            'docs/guides/audit-trail.md',
            [
                'every code your application records must have a definition registered with `AuditLog::define()` before it is recorded',
                'AuditLog::define(EventDefinition::for(\'orders.shipped\')->category(\'orders\'));',
                '`AuditLog::record(\'orders.shipped\')`, its code defined as [Codes](#codes) shows',
            ],
            [],
        ];

        yield 'a direct install defines its audit codes before turning registration on' => [
            'docs/guides/installation.md',
            [
                'every audit code your application records itself must have a definition registered with `AuditLog::define()` before it is recorded',
                'Before you turn it on, register a definition with `AuditLog::define()` for every audit code your application records itself',
                '| Define every audit code your application records itself |',
            ],
            [],
        ];

        yield 'MFA\'s codes take laravel-authentication\'s path only while its sender is bound' => [
            'docs/guides/authentication-and-mfa.md',
            [
                'only while `laravel-authentication`\'s one-time code sender is bound',
                'Otherwise MFA sends the code itself, synchronously, inside MFA\'s transaction, so a gateway that throws leaves no code and nothing is queued or retried.',
                'counted by MFA\'s challenge counters, while its one-time code sender is bound',
            ],
            ['is issued through `laravel-authentication`\'s factor codes, and delivered from its queued job'],
        ];

        yield 'a prefixed namesake of an authorization migration is only noted' => [
            'docs/guides/installation.md',
            [
                'One namesake does not fail the run: a namesake of one of `laravel-authorization`\'s migrations (`create_roles_table`, say) in a run that writes the table prefix',
                'is reported as a note, since the two then create different tables, unless an `AUTHORIZATION_TABLE_*` variable you set names the table yours creates',
            ],
            ['(`create_roles_table`, say) is not taken for the member\'s'],
        ];

        yield 'iam:check says no authorization decision is recorded yet' => [
            'docs/guides/checks.md',
            ['Until then **no authorization decision is recorded**, your own `Gate` checks included', '`SineMacula\Laravel\Authorization\Events\AuthorizationFailed`'],
            ['decisions are recorded through their own events'],
        ];

        yield 'the audit trail says no authorization decision is recorded yet' => [
            'docs/guides/audit-trail.md',
            [
                '**no authorization decision is recorded**: neither `laravel-authorization`\'s nor those of your own `Gate` checks',
                '`SineMacula\Laravel\Authorization\Events\AuthorizationFailed`',
            ],
            ['decisions will be mapped'],
        ];

        yield 'the routes owed follow this package\'s example application' => [
            'docs/guides/installation.md',
            [
                '| Add the routes, following laravel-iam\'s example application guide: redeem SSO\'s handoffs through'
                    . ' `Iam::signIns()`, `Iam::reauthentications()` and `Iam::links()`, never `HandoffRedemption` directly |',
            ],
            ['laravel-sso\'s example application guide'],
        ];

        yield 'the example lays out the flows this package changes, and links to the rest' => [
            self::EXAMPLE,
            [
                'serves the flows this package changes',
                '## Flows the members lay out',
                'never inside `Iam::transaction()` or a transaction of your own, and when one fails to serialise or deadlocks, retry the request',
                'Takes `mfa.remove_factor` freshness.',
                'behind `authentication.refresh`',
            ],
            ['every flow the suite offers'],
        ];

        yield 'the index does not claim every flow for the example' => [
            'docs/guides/README.md',
            ['Routes and controllers for the flows this package changes'],
            ['Routes and controllers for every flow'],
        ];

        yield 'a link asks for SSO\'s link confirmation' => [
            'docs/guides/authentication-and-sso.md',
            ['SSO asks three things of the link', '`SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation`'],
            ['SSO asks two things of the link'],
        ];

        yield 'a guard with its own signing keys is listed, rotated and revoked in its own block' => [
            'docs/guides/operations.md',
            [
                '| `auth.guards.<name>.jwt.keys`, `auth.guards.<name>.jwt.active_kid` | `laravel-authentication` | the signature of that guard\'s tokens',
                'A `jwt` guard whose `config/auth.php` entry sets its own `jwt.keys` signs and verifies its tokens with that map alone',
                'so it is rotated, and a compromised key revoked, in that guard\'s own block: removing a kid from `authentication.jwt.keys` revokes nothing that guard signed',
                'so a guard that overrides `keys` must also set its own `active_kid` to a kid in its own map',
                '[per-guard JWT configuration][auth-per-guard-jwt]',
            ],
            [],
        ];

        yield 'every code is delivered by a queue worker, and the install owes one' => [
            'docs/guides/installation.md',
            ['| Run a queue worker for `laravel-authentication`\'s code delivery and, while SSO is in use, SSO\'s metadata refresh | [Operations](operations.md#queues) |'],
            ['run a queue worker for SSO\'s metadata refresh'],
        ];

        yield 'the quick start asks for the queue worker that delivers every code' => [
            'docs/guides/README.md',
            ['a queue worker for `laravel-authentication`\'s delivery of one-time codes (`authentication.delivery.queue.connection` and `authentication.delivery.queue.name`'],
            [],
        ];

        yield 'a sync job keeps the state of the request that dispatched it' => [
            'docs/guides/configuration.md',
            ['before each queued job not on the `sync` connection, which runs inside the request that dispatched it'],
            ['and before each job.'],
        ];

        yield 'the configuration file says a sync job is skipped and the workers forget the scoped instances' => [
            'config/iam.php',
            [
                'before each queued job not on the `sync` connection',
                'Octane and the queue worker forget the container\'s',
                '(`false`, `0`, `off`, `no`)',
            ],
            ['a member\'s scoped instance) reaches the next', '(`false`, `0`, `off`) only'],
        ];

        yield 'SSO\'s freshness judges no caller handed in inside a transaction' => [
            'docs/guides/authentication-and-sso.md',
            [
                'Call `Iam::callers()->run()` with no transaction open on the storage connection, never inside `Iam::transaction()` or a transaction of your own',
                'a caller handed in inside one is `stale` until that transaction ends',
                'A caller signed in with a refresh or pending credential, or one holding a session of another guard or identity, is `stale`.',
            ],
            [],
        ];

        yield 'the configuration guide says the same of the caller scope' => [
            'docs/guides/configuration.md',
            [
                'a refresh or pending credential is `stale`',
                'Call `Iam::callers()->run()` with no transaction open on the storage connection: a caller handed in inside one is `stale` until that transaction ends.',
            ],
            [],
        ];

        yield 'the memberships example hands an immutable time of acceptance' => [
            'docs/guides/provisioning-and-tenancy.md',
            [
                'Membership::platform($member->accepted_at?->toImmutable())',
                'Membership::of((string) $member->tenant_id, $member->accepted_at?->toImmutable())',
                'an attribute cast as `datetime`, as Laravel casts a timestamp by default, is a mutable `Illuminate\Support\Carbon` that neither accepts',
            ],
            ['Membership::platform($member->accepted_at)', '$member->accepted_at)));'],
        ];

        yield 'the worker reset keeps the application\'s scoped bindings, and a loop forgets them itself' => [
            'docs/guides/operations.md',
            [
                'It forgets only the suite\'s scoped state: a scoped binding your application made, over a seam or of its own, is kept',
                'Iam::resetWorkerState(); app()->forgetScopedInstances();',
            ],
            [],
        ];

        yield 'the bindings guide sends request state to a scoped binding a loop forgets' => [
            'docs/guides/bindings.md',
            ['`Iam::resetWorkerState()` forgets only the suite\'s own, so a loop of your own also calls the container\'s `forgetScopedInstances()`'],
            [],
        ];

        yield 'the configuration guide says what the worker reset forgets' => [
            'docs/guides/configuration.md',
            ['That reset forgets only the members\' and this package\'s scoped state, never a scoped binding your application made (over a seam or of its own)'],
            [],
        ];

        yield 'the worker reset keeps the caller a queued job carried' => [
            'docs/guides/operations.md',
            [
                'audit-log\'s execution frames and the caller a queued job carried (`Iam\Audit\JobCallers`)',
                'a reset called by hand inside a job keeps it',
                'this package\'s own scoped adapters and records (those scoped under the `iam.scoped:` prefix)',
            ],
            [],
        ];

        yield 'an audit access policy scopes a tenant as this package records it' => [
            'docs/guides/audit-trail.md',
            [
                'as `Reference::of(\'tenant\', $tenant->getTenantIdentifier())` (`Iam\Audit\References::TENANT_TYPE`)',
                'a scope built with `Reference::to($organisation)`, as a policy over your own models would, matches none of these records',
                '`withTenantless()` shows a viewer every such record, of every tenant\'s people, and `AccessScope::all()` shows every tenant\'s trail',
            ],
            [],
        ];

        yield 'replacing the audit access policy is said to decide who reads the trail' => [
            'docs/guides/authorization.md',
            ['Bind your own policy to let a viewer read what its scope allows; a policy that replaces `DenyAllPolicy` decides who reads every person\'s trail'],
            ['to let anyone read it'],
        ];

        yield 'a tenant MFA requirement or SSO\'s enforcement owes a tenant resolver' => [
            'docs/guides/provisioning-and-tenancy.md',
            [
                '## The tenant resolver',
                'requires binding a resolver that resolves every tenant id to the tenant whose `getTenantIdentifier()` is exactly that id',
                'This applies even when your principals only ever act in their own tenant',
                'every MFA-gated request from a session in a tenant throws `UnresolvedReferenceException`, even when the session acts in its principal\'s own tenant',
            ],
            [],
        ];

        yield 'the install owes the tenant resolver' => [
            'docs/guides/installation.md',
            [
                '| Bind `laravel-authentication`\'s `TenantResolver` before you name a tenant MFA requirement or turn SSO\'s enforcement on,'
                    . ' even if your principals act only in their own tenant |',
            ],
            [],
        ];

        yield 'iam:check refuses a tenant resolver left on its default' => [
            'docs/guides/checks.md',
            ['is still bound to SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant while SSO\'s enforcement is on or a tenant MFA requirement is named'],
            [],
        ];

        yield 'a tenant named for the caller needs a resolver, even the principal\'s own' => [
            'docs/guides/testing.md',
            [
                'A tenant named with `$tenant` must be resolvable by `laravel-authentication`\'s `TenantResolver` even when it is the principal\'s own tenant',
                'Leave `$tenant` out to act in the principal\'s own tenant without a resolver.',
            ],
            ['a resolver that answered at sign-in and not afterwards'],
        ];

        yield 'the move lines up the storage connection before it requires the package' => [
            'docs/guides/installation.md',
            [
                '1. Line up the storage connection first, before you require this package.',
                '`iam:install` and `migrate` among them',
                '2. Require this package.',
            ],
            ['6. Point your storage keys at one connection'],
        ];
    }

    /**
     * Each guide states the behaviour the code has, and none it does not.
     *
     * @param  string  $guide
     * @param  list<string>  $present
     * @param  list<string>  $absent
     * @return void
     */
    #[DataProvider('provideStatements')]
    public function testTheGuideStatesWhatTheCodeDoes(string $guide, array $present, array $absent): void
    {
        $contents = self::flowed($guide);

        foreach ($present as $statement) {
            self::assertStringContainsString($statement, $contents, sprintf('%s does not state: %s', $guide, $statement));
        }

        foreach ($absent as $statement) {
            self::assertStringNotContainsString($statement, $contents, sprintf('%s still states: %s', $guide, $statement));
        }
    }

    /**
     * The fenced PHP blocks of a file.
     *
     * @param  string  $file
     * @return list<string>
     */
    private static function phpBlocks(string $file): array
    {
        preg_match_all(self::PHP_BLOCK, self::contents($file), $matches);

        return $matches[1];
    }

    /**
     * The file's contents with each run of whitespace, line breaks and the
     * indentation of list items among it, read as one space, so a statement
     * wrapped across lines is found as it reads.
     *
     * @param  string  $file
     * @return string
     */
    private static function flowed(string $file): string
    {
        return (string) preg_replace('/\s+/', ' ', self::contents($file));
    }

    /**
     * The contents of a file of the repository.
     *
     * @param  string  $file
     * @return string
     */
    private static function contents(string $file): string
    {
        $contents = file_get_contents(self::root() . '/' . $file);

        return is_string($contents) ? $contents : self::fail(sprintf('%s cannot be read.', $file));
    }

    /**
     * Every guide, relative to the repository.
     *
     * @return list<string>
     */
    private static function guides(): array
    {
        $guides = glob(self::root() . '/docs/guides/*.md') ?: [];

        return array_map(static fn (string $path): string => substr($path, strlen(self::root()) + 1), $guides);
    }

    /**
     * The repository's root.
     *
     * @return string
     */
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }
}
