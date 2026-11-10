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
 * names it, every `Iam::callers()->of()` is handed the caller, and the
 * statements of the code's behaviour a reader relies on for security (what the
 * evidence gates count, what `laravel-authorization`'s defaults leave open,
 * what `iam:check` can find and reads, what rotating `APP_KEY` restarts or
 * ends, which keys sign a guard's tokens, which queue workers deliver what,
 * which jobs the worker reset skips and what it keeps, what replacing a binding
 * the package keeps risks, what moving onto the package replaces and in which
 * order, what the members' test fakes replace, which callers SSO's freshness
 * judges, what the authentication context reads inside a transaction, how the
 * audit trail names a tenant, and when a tenant resolver is owed) say what the
 * code does.
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

    /** @var string The pattern of a call that names a caller to SSO, and its argument. */
    private const string CALLER_NAMED = '/Iam::callers\(\)->of\(\s*(\$\w+)/';

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
     * The example names the caller to SSO as the redemption names it, by the
     * identity's primary key, never by its auth identifier, which a model may
     * keep in another column.
     *
     * @return void
     */
    public function testTheExampleNamesTheCallerToSsoByItsKey(): void
    {
        $contents = self::contents(self::EXAMPLE);

        self::assertStringNotContainsString('getAuthIdentifier()', $contents);
        self::assertStringContainsString('Iam::callers()->of($caller)', $contents);
    }

    /**
     * Every `Iam::callers()->of()` the guides and the configuration file show
     * is handed the caller, as the method takes it.
     *
     * @return void
     */
    public function testEveryNamedCallerIsHandedTheCaller(): void
    {
        $arguments = [];

        foreach ([...self::guides(), 'config/iam.php'] as $file) {

            preg_match_all(self::CALLER_NAMED, self::contents($file), $matches);

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
        yield 'the example application answers both step-up exceptions with one renderer' => [
            self::EXAMPLE,
            ['this package renders it as MFA\'s step-up exception on Laravel\'s own handler, so', 'the one renderer above answers both'],
            ['does not map it to MFA', 'not map it to MFA\'s yet', 'so render it too'],
        ];

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

        yield 'the MFA guide says the context carries the mfa namespace, from the session it was built for' => [
            'docs/guides/authentication-and-mfa.md',
            [
                'carries MFA\'s view of the session under `mfa`',
                'another session, or in a queued job, reports that session\'s verification',
                '`iam:check` requires the namespace either way',
            ],
            ['has no `mfa` namespace yet', 'Until then read'],
        ];

        yield 'the MFA guide says the context is built once and kept, so a transaction reads its proofs only on the first build' => [
            'docs/guides/authentication-and-mfa.md',
            [
                '`Auth::context()` is built once per guard per request and kept',
                'forgets only when the guard binds another identity, principal or session, or when this process changes the session\'s proofs',
                'only when that first build happens inside a transaction on the session model\'s connection',
                'ask there through `Auth::sessions($guard)->proofs()` and `firstFactor()`, or MFA\'s own view, `Mfa::authenticationContext($caller)`',
            ],
            ['so read the context there only where you would take that lock'],
        ];

        yield 'the MFA design note says the context\'s read mode holds only for its first build' => [
            'docs/design/authentication-and-mfa.md',
            [
                'builds `Auth::context()` once per request and keeps it',
                'a later read runs no contributor, takes no lock and reads nothing',
                'never `Auth::context()`',
            ],
            ['so a context built inside a transaction takes the session row'],
        ];

        yield 'the context check requires the mfa namespace' => [
            'docs/guides/checks.md',
            [
                'the `mfa` namespace is required in every application',
                '*No contributor is registered under the `mfa` namespace of the authentication context; turn `iam.adapters.mfa` on,',
            ],
            ['joins the context check once this package contributes it', 'Applies while SSO is in use.'],
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
                'Yours is kept. An implementation that answers `within_tenant` for a person whose grants (platform-wide ones included) reach beyond the tenant',
                'lets that tenant\'s verified domain link the person, so its provider can sign in as them',
                'and takes this one out of SSO\'s boot',
            ],
            ['None of them is yours to replace', 'until `laravel-authorization`\'s grant scope query is bound'],
        ];

        yield 'iam:check cannot find a binding made in the application\'s providers' => [
            'docs/guides/installation.md',
            ['replaces the adapter silently, and is checked only if the seam is mandatory'],
            ['`iam:check` notes each seam it kept with'],
        ];

        yield 'authorization decides in the caller\'s tenant, and refuses no resource for its own unless told' => [
            'docs/guides/authorization.md',
            [
                '`laravel-authorization` decides in the caller\'s active tenant',
                'It still refuses **no resource for its tenant** unless you tell it which tenant owns each record',
                '`SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant`',
                '`iam:check` notes the default resolver left in place',
            ],
            ['decides with **no active tenant**', 'binds nothing of it yet', 'named by `iam:install`'],
        ];

        yield 'nothing of laravel-authorization\'s glue waits any more' => [
            'docs/guides/authorization.md',
            [
                'this package forgets that last decision if it read an authentication requirement in that session',
                'There is nothing else to invalidate: no decision is cached',
                'aligns with the other members\' keys',
                '`Iam::schedule()` registers `authorization:prune` daily',
            ],
            ['## What waits', 'which this package does not align yet', 'Check every SSO, MFA and audit-log administrative call yourself'],
        ];

        yield 'only MFA produces step-up responses, and the gate still comes first' => [
            'docs/guides/authorization.md',
            [
                'renders it as MFA\'s `InsufficientAuthenticationException`',
                'only MFA produces step-up responses',
                'A refusal none of whose requirements MFA can express stays Laravel\'s `403`',
                'Put the gate before `laravel-authorization`\'s',
            ],
            ['Each is a separate exception, and you answer both'],
        ];

        yield 'a class named in laravel-authorization\'s configuration is kept' => [
            'docs/guides/authorization.md',
            [
                'A class you name in',
                'in whatever order the providers register',
                'before `laravel-authorization` registers or after',
            ],
            ['whatever this package does', 'is lost to its own provider', 'refuses each seam it took'],
        ];

        yield 'a machine named anywhere no credential caps it is allowed nothing' => [
            'docs/guides/authorization.md',
            [
                'whether or not it also implements `laravel-authorization`\'s',
                'caps any other machine by nothing',
            ],
            [],
        ];

        yield 'the bindings guide says the provider order changes nothing, laravel-authorization\'s rows included' => [
            'docs/guides/bindings.md',
            [
                'providers register in changes nothing.',
                'is your binding, and kept, in whatever order the',
            ],
            ['except for `laravel-authorization`\'s rows', 'registers is lost', 'left on the default, a machine is allowed nothing'],
        ];

        yield 'an application left out of the access map is open to every principal, and a machine is admitted on its grants' => [
            'docs/guides/authorization.md',
            [
                '**An application the map does not name is open to every principal**',
                'A machine principal is admitted on its grants as a person is',
                'any other application to every principal',
            ],
            ['leave the applications your machines call out of the map', 'A machine principal is refused'],
        ];

        yield 'the design note says an application left out of the access map is open to every principal' => [
            'docs/design/authorization.md',
            ['An application the map does not name is open to every principal, people included, whatever its grants'],
            ['an application whose machines call it is left out of the map'],
        ];

        yield 'an identity that is no principal is its own subject' => [
            'docs/guides/authorization.md',
            [
                'An identity that is neither the caller\'s nor a principal itself, and any',
                'is its own subject, in no tenant and with no session',
                'reaches a grant hook as a grant to the identity itself',
            ],
            ['since it may act as several principals', 'name the principal instead'],
        ];

        yield 'a subject with no session is never judged, so a deny its requirement guards never refuses it' => [
            'docs/guides/authorization.md',
            [
                '**A subject with no session is never judged.**',
                'requirement guards applies to them. A deny guarded by a requirement therefore never refuses a subject with no session',
                'To refuse the caller\'s own sessionless checks, say so: deny them with a condition on `authentication.credential` or `authentication.session_id`',
                'A requirement that cannot be judged for a session makes its test undecidable',
            ],
            ['`unclassified`), a subject with no session'],
        ];

        yield 'the authentication context is the caller\'s, so it cannot refuse a check about a named principal' => [
            'docs/guides/authorization.md',
            [
                '**The context is always the request\'s own caller\'s.**',
                'never the subject a check names',
                'That condition cannot refuse a check about a principal you name',
                'Nothing in the authentication context can refuse such a check.',
                'deny it with a condition on a `subject.*` attribute',
            ],
            ['To refuse those, say so: deny them with a condition on'],
        ];

        yield 'the design note says the authentication context is the caller\'s' => [
            'docs/design/authorization.md',
            [
                'is always the request\'s own caller\'s',
                'no such condition refuses a check about a named principal while the caller holds a session',
            ],
            ['the guide tells an application to deny those explicitly'],
        ];

        yield 'an identity MFA reads as inactive meets no authorization requirement' => [
            'docs/guides/authorization.md',
            ['An identity MFA treats as inactive meets no requirement, as at MFA\'s own route gate'],
            [],
        ];

        yield 'the design note says an inactive identity meets no requirement' => [
            'docs/design/authorization.md',
            ['An identity MFA reads as inactive (its bound `ActiveStateResolver`'],
            [],
        ];

        yield 'the installation guide names the three adapter switches' => [
            'docs/guides/installation.md',
            ['Three switches turn the package\'s adapters off altogether, `IAM_ADAPTERS_MFA`, `IAM_ADAPTERS_SSO` and `IAM_ADAPTERS_AUTHORIZATION`'],
            ['Two switches'],
        ];

        yield 'the bindings guide says what turning each of the three switches off leaves' => [
            'docs/guides/bindings.md',
            ['Turning `iam.adapters.mfa`, `iam.adapters.sso` or `iam.adapters.authorization` off leaves every seam of its groups'],
            ['Two switches', 'Turning `iam.adapters.mfa` or `iam.adapters.sso` off'],
        ];

        yield 'a listing in the caller\'s scope is judged as the check is' => [
            'docs/guides/authorization.md',
            ['so `permissionsFor()` in the caller\'s scope lists exactly what `can()` allows'],
            [],
        ];

        yield 'the design note says a subject with no session never reaches the checker' => [
            'docs/design/authorization.md',
            ['A subject with no session never reaches the checker', 'neither an allow nor a deny the requirement guards applies'],
            ['A subject with no session or guard', 'throws, since its principal cannot be told'],
        ];

        yield 'a refusal about a named subject is no step-up' => [
            'docs/guides/authorization.md',
            ['and so does a refusal about a subject you name (`Authorization::for($account)->authorize()`)', 'only a refusal decided on the caller\'s own session asks for one'],
            [],
        ];

        yield 'the configuration file says a machine is capped by nothing with the authorization switch off' => [
            'config/iam.php',
            ['then capped by nothing, its credential\'s scopes ignored, unless it', 'implements `laravel-authorization`\'s `AuthorizableMachine`, which is'],
            ['a machine is | allowed nothing', 'a machine is allowed nothing'],
        ];

        yield 'the example warns that authorize: isolates no tenant' => [
            self::EXAMPLE,
            ['**No tenant isolation from `authorize:` or `permission:` until a record names its tenant.**'],
            ['**No tenant isolation from `authorize:` or `permission:` yet.**'],
        ];

        yield 'the audit trail is read through the viewer\'s grants' => [
            'docs/guides/audit-trail.md',
            [
                '(`SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter`)',
                'only the viewer\'s own activity, as the actor or the subject of a record',
                'no viewer sees records with no tenant, which may be about any tenant\'s people',
                'a tenant whose own policies deny the purpose is left out',
            ],
            ['nothing answers audit-log\'s access policy yet'],
        ];

        yield 'the seams left on their defaults include the refusing one' => [
            'docs/guides/bindings.md',
            [
                '`Authentication\Contracts\TenantAccess` is not `laravel-authorization`\'s to answer',
                '| `AuditLog\Contracts\AuditAccessPolicy`',
            ],
            [
                'which a later release of this package answers',
                'Two more wait the same way',
                'will be answered from the credential\'s scopes',
                'One more waits on a member default that refuses',
            ],
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

        yield 'iam:check says Gate capture would record the mapped decisions again' => [
            'docs/guides/checks.md',
            ['This package maps `laravel-authorization`\'s decision events, the `Gate` checks it answers among them'],
            ['Until then **no authorization decision is recorded**', 'after a later release maps'],
        ];

        yield 'the audit trail records each authorization denial once' => [
            'docs/guides/audit-trail.md',
            [
                '- a denial, once, as `authorization.access_denied`, denied with `laravel-authorization`\'s reason code',
                'or your own `Gate` checks, since `laravel-authorization` answers the Gate;',
                'It records no other allow. A denial as `insufficient_authentication` is recorded as `authorization.access_denied` too,',
            ],
            [
                '**no authorization decision is recorded**',
                'decisions will be mapped',
                'after a later release maps',
                'nor a denial as `insufficient_authentication`',
            ],
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

        yield 'a link asks for SSO\'s link confirmation, which the package answers' => [
            'docs/guides/authentication-and-sso.md',
            [
                'SSO asks three things of the link',
                '`SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation`',
                'signed in with a password or a passkey, or through your own account recovery',
                'A session any provider established is not, whichever link it stood on',
                'from a `FirstFactor` on the `recovery` channel (`ChannelKind::RECOVERY`',
                'a session started on any other channel, `unknown` included, does not',
            ],
            ['SSO asks two things of the link', 'This package does not answer it yet', 'stays bound', '`iam.sso.recovery_methods`'],
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

        yield 'SSO\'s freshness judges no session of a caller named inside a transaction' => [
            'docs/guides/authentication-and-sso.md',
            [
                'Call `Iam::callers()->of()` with no transaction open on the storage connection, never inside `Iam::transaction()` or a transaction of your own',
                'a caller named inside one carries no session, so it is `stale`',
                'A caller signed in with a refresh or pending credential, or one holding a session of another guard or identity, is `stale`.',
            ],
            ['Iam::callers()->run('],
        ];

        yield 'the configuration guide says the same of the named caller' => [
            'docs/guides/configuration.md',
            [
                'a refresh or pending credential is `stale`',
                'Call `Iam::callers()->of()` with no transaction open on the storage connection: a caller named inside one carries no session, so it is `stale`.',
            ],
            ['Iam::callers()->run('],
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
            ['a policy that replaces this package\'s decides who reads every person\'s trail'],
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
                '| Bind `laravel-authentication`\'s `TenantResolver` before you grant in a tenant while the authorization and SSO adapters are on'
                    . ' (the default), name a tenant MFA requirement or turn SSO\'s enforcement on, even if your principals act only in their own tenant |',
            ],
            [],
        ];

        yield 'iam:check refuses a tenant resolver left on its default' => [
            'docs/guides/checks.md',
            ['SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant while SSO\'s enforcement is on, a tenant MFA requirement is'],
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
