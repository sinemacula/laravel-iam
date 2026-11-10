<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization`'s session policy source
 * answered from the scopes of the caller's credential (IAM-6.5, AUTH-4.5): a
 * service account's API key caps the checks about the account by the scopes it
 * was issued, an empty list included, and a person's session caps nothing;
 * only the credential the subject's own guard holds for that very subject, and
 * that very session where the subject names one, is ever read, so a machine the
 * caller names for another principal or another session, or naming no guard, is
 * allowed nothing, and a person, or a guard that is not
 * `laravel-authentication`'s, is answered with no cap. Outside a request there
 * is no credential to read, and a machine is allowed nothing.
 *
 * The credentials are real ones: an API key `laravel-authentication` issues and
 * authenticates, and a session a person signs in to with a password. The source
 * only reads what the guard already admitted, so no read mode applies to it; it
 * is run on every engine at the connection's own level.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPolicySourceAdapter::class)]
final class SessionPolicySourceAdapterTest extends TestCase
{
    use MigratesAuthorization, SignsInPeople;

    /** @var string The guard service accounts authenticate on with an API key. */
    private const string KEYS = 'keys';

    /** @var string The route a test asks the source on. */
    private const string ROUTE = '/scopes';

    /**
     * Declare the guard service accounts authenticate on, and bind the source,
     * as an application would.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $config = $this->app?->make('config');

        $config?->set('auth.guards.' . self::KEYS, ['driver' => 'api_key', 'provider' => 'service-accounts', 'application' => ['methods' => ['api_key']]]);
        $config?->set('auth.providers.service-accounts', ['driver' => 'model', 'model' => ServiceAccount::class]);

        $this->app?->bind(SessionPolicySource::class, SessionPolicySourceAdapter::class);
    }

    /**
     * Rows of `[the scopes the key is issued]`.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideIssuedScopes(): iterable
    {
        yield 'two scopes' => [['reports:read', 'reports:export']];

        yield 'none' => [[]];
    }

    /**
     * A service account's API key caps the checks about the account by the
     * scopes it was issued, as `laravel-authentication` holds them, an empty
     * list, which allows nothing, included.
     *
     * @param  list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideIssuedScopes')]
    public function testAnApiKeyCapsItsAccountByItsScopes(array $scopes): void
    {
        $account = $this->createAccount();
        $key     = $this->issueKey($account, $scopes);

        $this->answerOn(static fn (): Subject => self::subjectOf(self::authenticated(), self::KEYS));

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])->assertExactJson(['scopes' => $scopes]);
    }

    /**
     * The account the guard holds is matched by its model, so a subject holding
     * another copy of the very account is capped alike.
     *
     * @return void
     */
    public function testACopyOfTheAccountTheGuardHoldsIsCappedAlike(): void
    {
        $account = $this->createAccount();
        $key     = $this->issueKey($account, ['reports:read']);

        $this->answerOn(static fn (): Subject => self::subjectOf(ServiceAccount::query()->findOrFail($account->id), self::KEYS));

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])->assertExactJson(['scopes' => ['reports:read']]);
    }

    /**
     * A machine the caller names for another principal than the one the guard
     * holds, one naming no guard, and one naming a guard that is not the one
     * holding the credential, are allowed nothing: no credential of theirs is
     * held, and a machine is never left uncapped.
     *
     * @return void
     */
    public function testAMachineTheGuardDoesNotHoldIsAllowedNothing(): void
    {
        $account = $this->createAccount();
        $other   = $this->createAccount('Billing');
        $key     = $this->issueKey($account, ['reports:read']);

        $this->answerOn(static fn (): array => [
            'another account' => self::subjectOf($other, self::KEYS),
            'no guard'        => self::subjectOf(self::authenticated(), null),
            'another guard'   => self::subjectOf(self::authenticated(), self::GUARD),
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])->assertExactJson(['scopes' => [
            'another account' => [],
            'no guard'        => [],
            'another guard'   => [],
        ]]);
    }

    /**
     * A machine naming a session the guard does not hold is allowed nothing,
     * even the very account the guard holds: the guard holds no credential for
     * that session.
     *
     * @return void
     */
    public function testAMachineNamingASessionTheGuardDoesNotHoldIsAllowedNothing(): void
    {
        $account = $this->createAccount();
        $key     = $this->issueKey($account, ['reports:read']);

        $this->answerOn(static fn (): Subject => self::subjectOf(self::authenticated(), self::KEYS, 'a-session-of-another-credential'));

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])->assertExactJson(['scopes' => []]);
    }

    /**
     * A person's session caps nothing, for the subject naming the session the
     * guard holds; and a subject naming another session of the person's carries
     * no cap either.
     *
     * @return void
     */
    public function testAPersonsSessionCapsNothing(): void
    {
        $token = $this->signIn($this->createPerson())->tokens->accessToken->reveal();

        $this->answerOn(static function (): array {

            $session = self::guard(self::GUARD)->session()?->getSessionIdentifier();

            assert(is_string($session) || is_int($session));

            $person = self::authenticated(self::GUARD);

            return [
                'its session'      => self::subjectOf($person, self::GUARD, (string) $session),
                'another session'  => self::subjectOf($person, self::GUARD, 'another'),
                'no session named' => self::subjectOf($person, self::GUARD),
            ];
        }, self::GUARD);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $token])->assertExactJson(['scopes' => [
            'its session'      => null,
            'another session'  => null,
            'no session named' => null,
        ]]);
    }

    /**
     * A guard that is not one of `laravel-authentication`'s contextual guards
     * holds no credential the source can read, so its subject carries no cap.
     *
     * @return void
     */
    public function testAGuardThatIsNotContextualCarriesNoCap(): void
    {
        $this->app?->make('config')->set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);

        self::assertNull($this->source()->scopesFor(self::subjectOf($this->createPerson(), 'web')));
    }

    /**
     * Outside a request no guard holds a credential, so a service account is
     * answered a cap allowing nothing.
     *
     * @return void
     */
    public function testOutsideARequestNoCredentialIsHeld(): void
    {
        self::assertSame([], $this->source()->scopesFor(self::subjectOf($this->createAccount(), self::KEYS)));
    }

    /**
     * A guard that has not resolved its request yet holds no credential the
     * source may read, so even the account whose key the request presents is
     * allowed nothing, and the guard's resolution is not started: it still
     * holds no one once the source has answered.
     *
     * @return void
     */
    public function testAGuardThatHasNotResolvedItsRequestIsNotResolvedForTheSource(): void
    {
        $account = $this->createAccount();
        $key     = $this->issueKey($account, ['reports:read']);

        Route::get(self::ROUTE, fn (): array => [
            'scopes'   => $this->source()->scopesFor(self::subjectOf($account, self::KEYS)),
            'resolved' => self::guard(self::KEYS)->hasUser(),
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])->assertExactJson(['scopes' => [], 'resolved' => false]);
    }

    /**
     * A guard the subject names that is not configured is refused with the
     * guard's own exception, and no answer is made up.
     *
     * @return void
     */
    public function testAGuardThatIsNotConfiguredIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->source()->scopesFor(self::subjectOf($this->createAccount(), 'unknown'));
    }

    /**
     * Load the application's configuration, then declare the report permissions
     * before any provider registers, so the scope registry lets a key carry
     * them.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('authorization.permission_enums', [ReportPermission::class]);
    }

    /**
     * Serve the route that answers the source's scopes for the subject, or for
     * each subject, the callback makes once the guard given has authenticated
     * the request.
     *
     * @param  \Closure(): (array<string, \SineMacula\Laravel\Authorization\Subject>|\SineMacula\Laravel\Authorization\Subject)  $subjects
     * @param  string  $guard
     * @return void
     */
    private function answerOn(\Closure $subjects, string $guard = self::KEYS): void
    {
        Route::get(self::ROUTE, function (Request $request) use ($subjects, $guard): array {

            self::assertTrue(Auth::guard($guard)->check());

            $made   = $subjects();
            $source = $this->source();

            return ['scopes' => is_array($made) ? array_map($source->scopesFor(...), $made) : $source->scopesFor($made)];
        });
    }

    /**
     * The source the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\SessionPolicySource
     */
    private function source(): SessionPolicySource
    {
        return $this->app?->make(SessionPolicySource::class) ?? self::fail('The application has not booted.');
    }

    /**
     * Create a service account.
     *
     * @param  string  $name
     * @return \Tests\Fixtures\Authorization\ServiceAccount
     */
    private function createAccount(string $name = 'Reporting'): ServiceAccount
    {
        return ServiceAccount::query()->create(['name' => $name]);
    }

    /**
     * Issue the account an API key on the keys guard with the scopes given, and
     * answer the key it presents.
     *
     * @param  \Tests\Fixtures\Authorization\ServiceAccount  $account
     * @param  list<string>  $scopes
     * @return string
     */
    private function issueKey(ServiceAccount $account, array $scopes): string
    {
        return Auth::apiKeys(self::KEYS)->issue($account, $account, $scopes)->key()->reveal();
    }

    /**
     * The principal the guard given holds.
     *
     * @param  string  $guard
     * @return object
     */
    private static function authenticated(string $guard = self::KEYS): object
    {
        return self::guard($guard)->principal() ?? self::fail('The guard holds no principal.');
    }

    /**
     * The `laravel-authentication` guard of the name given.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
     */
    private static function guard(string $guard): ContextualGuard
    {
        $resolved = Auth::guard($guard);

        self::assertInstanceOf(ContextualGuard::class, $resolved);

        return $resolved;
    }

    /**
     * A subject of the principal on the guard, with the session given.
     *
     * @param  object  $principal
     * @param  ?string  $guard
     * @param  ?string  $session
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function subjectOf(object $principal, ?string $guard, ?string $session = null): Subject
    {
        return new Subject(subject: $principal, identity: $principal, tenant: null, application: $guard, guard: $guard, session: $session);
    }
}
