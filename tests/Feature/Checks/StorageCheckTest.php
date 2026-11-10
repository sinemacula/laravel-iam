<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Checks\StorageCheck;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Checks\IdentityElsewhere;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Feature tests for the storage check (IAM-2.3) at deploy: every member
 * registered, every member key on the shared connection, the shared connection
 * configured, every identity model on it, and audit-log's connection noted when
 * it is another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageCheck::class)]
final class StorageCheckTest extends TestCase
{
    use RunsChecks;

    /** @var string A connection the shared one is not. */
    private const string ELSEWHERE = 'elsewhere';

    /**
     * The application the tests boot, every member and its identity model on
     * the default connection, passes with nothing to note.
     *
     * @return void
     */
    public function testOneConnectionPasses(): void
    {
        $checks = $this->check()->checks();

        self::assertSame([], self::problems($checks));
        self::assertSame([], self::notes($checks));
        self::assertTrue($this->check()->applies());
        self::assertSame('storage', $this->check()->subject());
    }

    /**
     * A member key naming another connection is reported.
     *
     * @return void
     */
    public function testAMemberKeyOnAnotherConnectionFails(): void
    {
        $this->configureElsewhere();
        $this->config()->set('mfa.storage.connection', self::ELSEWHERE);

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringContainsString('mfa.storage.connection', $problems[0]);
    }

    /**
     * A shared connection `database.connections` does not configure is
     * reported, with the identity model left on the default connection.
     *
     * @return void
     */
    public function testAnUnconfiguredSharedConnectionFails(): void
    {
        $config = $this->config();

        $config->set('iam.storage.connection', 'missing');
        $config->set('authentication.storage.connection', 'missing');
        $config->set('mfa.storage.connection', 'missing');
        $config->set('sso.storage.connection', 'missing');
        $config->set('authorization.connection', 'missing');

        self::assertSame([
            '`iam.storage.connection` names a connection `database.connections` does not configure.',
            'The identity model ' . Person::class . ' lives on another connection than `iam.storage.connection` names.',
        ], self::problems($this->check()->checks()));
    }

    /**
     * A member that never registered is reported, where `iam:check` runs, as
     * boot stands its refusal aside for it.
     *
     * @return void
     */
    public function testAMemberThatNeverRegisteredIsReported(): void
    {
        $this->withArguments(['artisan', 'iam:check']);
        $this->reorderProviders([
            AuthenticationServiceProvider::class,
            AuthorizationServiceProvider::class,
            MfaServiceProvider::class,
            AuditLogServiceProvider::class,
            IamServiceProvider::class,
        ]);

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringContainsString('sso.storage.connection', $problems[0]);
    }

    /**
     * An identity model on another connection, or no Eloquent model at all, is
     * reported once, however many guards sign people in through it; a guard of
     * another driver, or one whose provider names no model, is not read.
     *
     * @return void
     */
    public function testEveryIdentityModelMustLiveOnTheSharedConnection(): void
    {
        $config = $this->config();

        $config->set('auth.providers.elsewhere', ['driver' => 'model', 'model' => IdentityElsewhere::class]);
        $config->set('auth.providers.objects', ['driver' => 'model', 'model' => \stdClass::class]);
        $config->set('auth.providers.modelless', ['driver' => 'database', 'model' => '']);
        $config->set('auth.guards.elsewhere', ['driver' => 'jwt', 'provider' => 'elsewhere']);
        $config->set('auth.guards.again', ['driver' => 'api_key', 'provider' => 'elsewhere']);
        $config->set('auth.guards.objects', ['driver' => 'api_key', 'provider' => 'objects']);
        $config->set('auth.guards.modelless', ['driver' => 'jwt', 'provider' => 'modelless']);
        $config->set('auth.guards.unknown', ['driver' => 'jwt', 'provider' => 'unknown']);
        $config->set('auth.guards.nameless', ['driver' => 'jwt']);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'objects']);
        $config->set('auth.guards.broken', 'not a guard');

        self::assertSame([
            'The identity model ' . IdentityElsewhere::class . ' lives on another connection than `iam.storage.connection` names.',
            'The identity model stdClass is no Eloquent model.',
        ], self::problems($this->check()->checks()));
    }

    /**
     * A `jwt` or `api_key` guard naming no provider, or an empty one, signs
     * people in through the default user provider, as `laravel-authentication`
     * and Laravel resolve it, so its model is read: one on another connection
     * is reported. With no default provider, such a guard is not read, as
     * Laravel never reads a provider under an empty name.
     *
     * @return void
     */
    public function testAGuardNamingNoProviderReadsTheDefaultProvidersModel(): void
    {
        $config = $this->config();

        $config->set('auth.defaults.provider', null);
        $config->set('auth.providers', [...(array) $config->get('auth.providers'), '' => ['driver' => 'model', 'model' => IdentityElsewhere::class]]);
        $config->set('auth.providers.elsewhere', ['driver' => 'model', 'model' => IdentityElsewhere::class]);
        $config->set('auth.guards.nameless', ['driver' => 'jwt']);
        $config->set('auth.guards.empty', ['driver' => 'api_key', 'provider' => '']);

        self::assertSame([], self::problems($this->check()->checks()));

        $config->set('auth.defaults.provider', 'elsewhere');

        self::assertSame([
            'The identity model ' . IdentityElsewhere::class . ' lives on another connection than `iam.storage.connection` names.',
        ], self::problems($this->check()->checks()));

        $config->set('auth.defaults.provider', ['elsewhere']);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * With no guards configured, no identity model is read.
     *
     * @return void
     */
    public function testNoGuardsReadNoModels(): void
    {
        $config = $this->config();

        $config->set('auth.guards', null);
        $config->set('auth.providers', null);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * An identity model whose connection is named, the shared one by its own
     * name, passes.
     *
     * @return void
     */
    public function testAModelNamingTheSharedConnectionPasses(): void
    {
        $this->configureElsewhere();

        $config = $this->config();

        $config->set('iam.storage.connection', self::ELSEWHERE);
        $config->set('authentication.storage.connection', self::ELSEWHERE);
        $config->set('mfa.storage.connection', self::ELSEWHERE);
        $config->set('sso.storage.connection', self::ELSEWHERE);
        $config->set('authorization.connection', self::ELSEWHERE);
        $config->set('audit-log.storage.connection', self::ELSEWHERE);
        $config->set('auth.providers.people.model', IdentityElsewhere::class);

        self::assertSame([], self::problems($this->check()->checks()));
        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * Audit-log's storage connection, when it is another than the shared one,
     * is noted, which is no problem; left empty, it is the default one.
     *
     * @return void
     */
    public function testAuditLogOnAnotherConnectionIsNoted(): void
    {
        $config = $this->config();

        $config->set('audit-log.storage.connection', '');

        self::assertSame([], self::notes($this->check()->checks()));

        $config->set('audit-log.storage.connection', self::ELSEWHERE);

        $checks = $this->check()->checks();

        self::assertSame([], self::problems($checks));
        $note = '`audit-log.storage.connection` names another connection than `iam.storage.connection`: '
            . 'audit-log\'s refusal of a read of the trail inside a change does not cover it.';

        self::assertSame([$note], self::notes($checks));
    }

    /**
     * Configure the connection the shared one is not.
     *
     * @return void
     */
    private function configureElsewhere(): void
    {
        $this->config()->set('database.connections.' . self::ELSEWHERE, ['driver' => 'sqlite', 'database' => ':memory:']);
    }

    /**
     * The application's configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): Repository
    {
        $config = $this->app?->make('config');

        self::assertInstanceOf(Repository::class, $config);

        return $config;
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\StorageCheck
     */
    private function check(): StorageCheck
    {
        $check = $this->app?->make(StorageCheck::class);

        assert($check instanceof StorageCheck);

        return $check;
    }
}
