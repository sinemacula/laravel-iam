<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Checks\StorageCheck;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Checks\IdentityElsewhere;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Feature tests for the storage check.
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
     * Everything on the default connection passes with nothing to note.
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
     * A shared connection `database.connections` lacks is reported.
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
     * An identity model elsewhere, or no model at all, is reported once.
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
     * A guard naming no provider reads the default provider's model.
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
     * A model naming the shared connection explicitly passes.
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
     * Audit-log on another connection is noted, not failed.
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
