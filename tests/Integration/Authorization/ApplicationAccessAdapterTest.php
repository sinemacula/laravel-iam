<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Auth\SessionGuard;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Iam\Authorization\AccessMandates;
use SineMacula\Laravel\Iam\Authorization\ApplicationAccessAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Authorization\Seat;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\Fixtures\Authorization\Staff;
use Tests\TestCase;

/**
 * Integration tests for application access answered from grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationAccessAdapter::class)]
final class ApplicationAccessAdapterTest extends TestCase
{
    use MigratesAuthorization;

    /** @var string The permission to use the application people sign in on. */
    private const string USE = 'api:use';

    /**
     * Sign members in on the people guard and declare the permission.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->make('config')->set('auth.providers.people.model', Member::class);

        Permission::query()->create(['name' => self::USE]);
    }

    /**
     * The adapter is the application access the container builds.
     *
     * @return void
     */
    public function testTheAdapterIsTheApplicationAccess(): void
    {
        self::assertInstanceOf(ApplicationAccessAdapter::class, $this->access());
    }

    /**
     * A member signs in only with the permission to use the application.
     *
     * @return void
     */
    public function testAMemberSignsInOnlyWithThePermissionToUseTheApplication(): void
    {
        $member = $this->createMember();

        $refused = $this->attempt($member);

        self::assertFalse($refused->isSignedIn());
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $refused->reason);

        $member->givePermission(self::USE);

        self::assertTrue($this->attempt($member)->isSignedIn());
    }

    /**
     * A grant for another application does not count.
     *
     * @return void
     */
    public function testAGrantForAnotherApplicationDoesNotCount(): void
    {
        $member = $this->createMember();

        $member->givePermission(self::USE, application: 'admin');

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->attempt($member)->reason);

        $member->givePermission(self::USE, application: self::GUARD);

        self::assertTrue($this->attempt($member)->isSignedIn());
    }

    /**
     * An application the map does not name admits everyone.
     *
     * @return void
     */
    public function testAnApplicationTheMapDoesNotNameAdmitsEveryone(): void
    {
        $this->app?->make('config')->set(AccessMandates::APPLICATION_ACCESS, ['admin' => self::USE]);

        self::assertTrue($this->attempt($this->createMember())->isSignedIn());
    }

    /**
     * A withdrawn grant refuses the next refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWithdrawnGrantRefusesTheNextRefresh(): void
    {
        $member = $this->createMember();

        $member->givePermission(self::USE);

        $signedIn = $this->attempt($member);
        $refresh  = $signedIn->session?->tokens->refreshToken;

        self::assertNotNull($refresh);

        $member->revokePermission(self::USE);

        $refreshed = Auth::sessions(self::GUARD)->refresh(PresentedRefreshToken::fromBody($refresh), self::client());

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $refreshed->reason);
    }

    /**
     * A principal is admitted on its identity's grant, whatever the guard.
     *
     * @return void
     */
    public function testAPrincipalIsAdmittedOnItsIdentitysGrantWhicheverGuardIsTheDefault(): void
    {
        $staff = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $seat  = Seat::query()->create(['person_id' => $staff->id]);

        self::assertFalse($this->access()->mayUse(self::GUARD, $seat));

        $staff->givePermission(self::USE);

        self::assertTrue($this->access()->mayUse(self::GUARD, $seat));

        $this->app?->make('config')->set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);

        Auth::shouldUse('web');

        self::assertInstanceOf(SessionGuard::class, Auth::guard());
        self::assertTrue($this->access()->mayUse(self::GUARD, $seat));

        $staff->revokePermission(self::USE);

        self::assertFalse($this->access()->mayUse(self::GUARD, $seat));
    }

    /**
     * A machine is admitted on its own grants.
     *
     * @return void
     */
    public function testAMachineIsAdmittedOnAnApplicationTheMapNamesOnItsGrants(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'service-accounts', 'application' => ['methods' => ['api_key']]]);
        $config?->set('auth.providers.service-accounts', ['driver' => 'model', 'model' => ServiceAccount::class]);
        $config?->set(AccessMandates::APPLICATION_ACCESS, ['keys' => self::USE]);

        $account = ServiceAccount::query()->create(['name' => 'Reporting']);

        self::assertFalse($this->access()->mayUse('keys', $account));

        $account->givePermission(self::USE);

        self::assertTrue($this->access()->mayUse('keys', $account));

        $account->revokePermission(self::USE);

        self::assertFalse($this->access()->mayUse('keys', $account));
    }

    /**
     * Map the application to its permission and declare it.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $config = $app->make('config');

        $config->set('authorization.permission_enums', [ReportPermission::class]);
        $config->set(AccessMandates::APPLICATION_ACCESS, [self::GUARD => self::USE]);
    }

    /**
     * The application access the container builds.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationAccess
     */
    private function access(): ApplicationAccess
    {
        return $this->app?->make(ApplicationAccess::class) ?? self::fail('The application has not booted.');
    }

    /**
     * Create a member who signs in with the tests' password.
     *
     * @return \Tests\Fixtures\Authorization\Member
     */
    private function createMember(): Member
    {
        return Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada-' . uniqid() . '@example.test', 'password' => self::PASSWORD]);
    }

    /**
     * Sign the member in with a password on the guard people sign in on.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function attempt(Member $member): SignInResult
    {
        return Auth::sessions(self::GUARD)->signIn('password', ['email' => $member->email, 'password' => self::PASSWORD], new SignInContext(self::client()));
    }

    /**
     * The tests' client.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext('192.0.2.10', 'iam-tests');
    }
}
