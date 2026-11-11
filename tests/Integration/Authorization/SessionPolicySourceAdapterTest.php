<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\RecordingSessionPolicySource;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\Fixtures\Authorization\Staff;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization`'s session policy source
 * answered from the scopes of the caller's credential (IAM-6.5, AUTH-4.5),
 * which the subject resolver says on the subject and the source establishes
 * itself, failing closed, where a subject names a credential but says nothing
 * of its scopes. Through the facade, a check about a service account calling
 * with an API key is capped by the scopes the key was issued, an empty list
 * included, one about a person signed in to a session by nothing, and one about
 * a model the caller names carries none of the caller's scopes. Built by hand,
 * a subject naming a person's live session of its guard carries no cap, and one
 * naming a revoked session, another identity's, one of another guard or a key
 * that names none is allowed nothing; a subject naming the guard whose caller
 * it is, is capped by that caller's key, and one naming a guard whose caller is
 * someone else names no credential, so a person carries no cap and a
 * machine is allowed nothing; a guard that is not configured allows nothing;
 * and a job's person, naming neither, carries no cap.
 *
 * The credentials are real ones: an API key `laravel-authentication` issues and
 * authenticates, and sessions a person signs in to with a password, and each
 * check through the facade is asked of a source recording what it answered.
 * Each answer reads the session as stored, so no read mode is at stake; it is
 * run on every engine at the connection's own level.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPolicySourceAdapter::class)]
#[CoversClass(SubjectResolverAdapter::class)]
final class SessionPolicySourceAdapterTest extends TestCase
{
    use MigratesAuthorization, SignsInPeople;

    /** @var string The guard service accounts authenticate on with an API key. */
    private const string KEYS = 'keys';

    /** @var string Another guard people sign in on. */
    private const string PORTAL = 'portal';

    /** @var string The route a test asks its checks on. */
    private const string ROUTE = '/scopes';

    /** @var \Tests\Fixtures\Authorization\RecordingSessionPolicySource The bound source, recording what the adapter answers. */
    private RecordingSessionPolicySource $source;

    /**
     * Declare the guard service accounts authenticate on, another guard people
     * sign in on and the permission the accounts are granted, and bind the
     * source, recording its answers, as an application would bind it.
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
        $config?->set('auth.guards.' . self::PORTAL, ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => $this->signInMethods()]]);

        Permission::query()->create(['name' => 'reports:read']);

        $this->source = new RecordingSessionPolicySource(new SessionPolicySourceAdapter($this->app?->make(AuthFactory::class) ?? self::fail('The application has not booted.')));

        $this->app->instance(SessionPolicySource::class, $this->source);
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
     * A check about a service account calling with an API key reaches the
     * source with the scopes the key was issued, carried on the request's
     * subject, and is capped by them: an empty list allows nothing the account
     * is granted.
     *
     * @param  list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideIssuedScopes')]
    public function testAnApiKeysScopesReachTheSource(array $scopes): void
    {
        $account = $this->createAccount();

        $account->givePermission('reports:read');

        $key = $this->issueKey($account, $scopes);

        $this->askOn(self::KEYS, static fn (): array => [
            'subject' => Authorization::currentSubject()?->scopes?->scopes(),
            'allowed' => Authorization::can('reports:read'),
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])
            ->assertOk()
            ->assertExactJson(['subject' => $scopes, 'allowed' => in_array('reports:read', $scopes, true), 'answers' => [$scopes]]);
    }

    /**
     * A check about a person signed in to a session reaches the source saying
     * its credential carries no cap, so it is capped by nothing.
     *
     * @return void
     */
    public function testAPersonsSessionReachesTheSourceWithNoCap(): void
    {
        $token = $this->signIn($this->createPerson())->tokens->accessToken->reveal();

        $this->askOn(self::GUARD, static fn (): array => [
            'capped'  => Authorization::currentSubject()?->scopes?->isCapped(),
            'allowed' => Authorization::can('reports:read'),
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $token])
            ->assertOk()
            ->assertExactJson(['capped' => false, 'allowed' => false, 'answers' => [null]]);
    }

    /**
     * A subject the caller names for another model says nothing of its scopes
     * and names no session: a person named reaches the source with no cap, and
     * a machine named is allowed nothing, whatever the caller's key carries.
     *
     * @return void
     */
    public function testASubjectNamedForAnotherModelCarriesNoScopes(): void
    {
        $key    = $this->issueKey($this->createAccount(), ['reports:read']);
        $person = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $other  = $this->createAccount('Billing');

        $this->askOn(self::KEYS, static fn (): array => [
            'subject' => [Authorization::currentSubject()?->withSubject($person)->scopes, Authorization::currentSubject()?->withSubject($person)->session],
            'allowed' => [Authorization::for($person)->can('reports:read'), Authorization::for($other)->can('reports:read')],
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])
            ->assertOk()
            ->assertExactJson(['subject' => [null, null], 'allowed' => [false, false], 'answers' => [null, []]]);
    }

    /**
     * A subject built by hand naming a person's live session of the guard it
     * names, as the person's own, carries no cap: no session stands behind a
     * credential carrying scopes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonsLiveSessionCarriesNoCap(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertNull($this->source->scopesFor(new Subject($person, $person, guard: self::GUARD, session: self::keyOf($session))));
    }

    /**
     * A subject built by hand naming a session that is not the person's live
     * session of the guard it names is allowed nothing: a revoked session,
     * another identity's, one of another guard, or a key that names none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotThePersonsLiveSessionOfTheGuardAllowsNothing(): void
    {
        $person  = $this->createPerson();
        $other   = $this->createPerson();
        $revoked = self::keyOf($this->signIn($person)->record);

        Auth::sessions(self::GUARD)->revokeSession($person, $revoked, RevocationReason::REVOKED);

        $sessions = [
            'revoked'          => $revoked,
            'another identity' => self::keyOf($this->signIn($other)->record),
            'another guard'    => self::keyOf($this->signIn($person, self::PORTAL)->record),
            'made up'          => '999999',
        ];

        $answers = array_map(fn (string $session): ?array => $this->source->scopesFor(new Subject($person, $person, guard: self::GUARD, session: $session)), $sessions);

        self::assertSame(['revoked' => [], 'another identity' => [], 'another guard' => [], 'made up' => []], $answers);
        self::assertNull($this->source->scopesFor(new Subject($person, $person, guard: self::PORTAL, session: $sessions['another guard'])));
    }

    /**
     * A subject built by hand naming the guard whose caller it is, by another
     * copy of the very account, is capped by the caller's key, an empty list
     * included.
     *
     * @param  list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideIssuedScopes')]
    public function testASubjectNamingTheGuardWhoseCallerItIsIsCappedByItsKey(array $scopes): void
    {
        $account = $this->createAccount();
        $key     = $this->issueKey($account, $scopes);

        $this->askOn(self::KEYS, fn (): array => [
            'subject' => $this->source->scopesFor(new Subject(ServiceAccount::query()->findOrFail($account->id), guard: self::KEYS)),
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])->assertOk()->assertJsonPath('subject', $scopes);
    }

    /**
     * A subject built by hand naming a guard whose caller is someone else names
     * no credential of its own: another account is allowed nothing, and a
     * person carries no cap.
     *
     * @return void
     */
    public function testASubjectNamingAGuardWhoseCallerIsSomeoneElseNamesNoCredential(): void
    {
        $key    = $this->issueKey($this->createAccount(), ['reports:read']);
        $other  = $this->createAccount('Billing');
        $person = $this->createPerson();

        $this->askOn(self::KEYS, fn (): array => [
            'subject' => [
                $this->source->scopesFor(new Subject($other, guard: self::KEYS)),
                $this->source->scopesFor(new Subject($person, $person, guard: self::KEYS)),
            ],
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])->assertOk()->assertJsonPath('subject', [[], null]);
    }

    /**
     * A subject naming a guard that is not configured allows nothing, and the
     * source does not throw.
     *
     * @return void
     */
    public function testASubjectNamingAGuardThatIsNotConfiguredAllowsNothing(): void
    {
        $person = $this->createPerson();

        self::assertSame([], $this->source->scopesFor(new Subject($person, $person, guard: 'unknown')));
    }

    /**
     * A job's or a console command's person, naming neither a session nor a
     * guard, names no credential, and carries no cap.
     *
     * @return void
     */
    public function testAJobsPersonCarriesNoCap(): void
    {
        $person = $this->createPerson();

        self::assertNull($this->source->scopesFor(new Subject($person, $person)));
    }

    /**
     * Outside a request no credential is held, so a check about a service
     * account reaches the source with no scopes and is allowed nothing.
     *
     * @return void
     */
    public function testOutsideARequestAMachineIsAllowedNothing(): void
    {
        $account = $this->createAccount();

        $account->givePermission('reports:read');

        self::assertFalse(Authorization::for($account)->can('reports:read'));
        self::assertSame([[]], $this->source->answers);
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
     * Serve the route, authenticated on the guard given, that asks the checks
     * the callback makes and answers what it returns, with what the source
     * answered while it asked them.
     *
     * @param  string  $guard
     * @param  \Closure(): array<string, mixed>  $checks
     * @return void
     */
    private function askOn(string $guard, \Closure $checks): void
    {
        Route::middleware('auth:' . $guard)->get(self::ROUTE, function () use ($checks): array {

            $this->source->answers = [];

            return [...$checks(), 'answers' => $this->source->answers];
        });
    }

    /**
     * The session's key, as a subject names it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return string
     */
    private static function keyOf(Model $session): string
    {
        $key = $session->getKey();

        self::assertTrue(is_string($key) || is_int($key));

        return (string) $key;
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
}
