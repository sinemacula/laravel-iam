<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * Integration tests of a deny statement guarded by an authentication
 * requirement (IAM-6.3), as the guides describe it: a subject with no session
 * is never handed to the requirement checker, so
 * `laravel-authorization` finds the requirement unmet and the deny does not
 * apply to it, even where asking the checker would have thrown; a subject whose
 * session the checker cannot judge, so that it throws, makes the deny
 * undecidable, and the deny applies; and a session the checker judges, not
 * stepped up, leaves the requirement unmet, so the deny does not apply.
 *
 * The session is a real one, signed in through `laravel-authentication`, whose
 * proofs the checker reads, so it runs at the connection's own level on every
 * engine, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementCheckerAdapter::class)]
final class RequirementGuardedDenyTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The action a deny guards with a requirement the checker cannot judge. */
    private const string REFUND = 'invoices:refund';

    /** @var string The action a deny guards with a requirement the checker judges. */
    private const string VOID = 'invoices:void';

    /**
     * A subject with no session is not refused by either deny, a check whose
     * requirement the checker throws for is, and one whose requirement the
     * checker finds unmet is not.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testADenyAppliesOnlyWhereItsRequirementIsUndecidable(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $member  = $this->member();
        $session = new Subject($member, $member, null, self::GUARD, self::GUARD, $this->signIn($member));

        self::assertTrue(Authorization::for($member)->can(self::REFUND));
        self::assertTrue(Authorization::for($member)->can(self::VOID));
        self::assertTrue(Authorization::for(new Subject($member, $member, null, self::GUARD, self::GUARD))->can(self::REFUND));

        self::assertFalse(Authorization::for($session)->can(self::REFUND));
        self::assertTrue(Authorization::for($session)->can(self::VOID));
    }

    /**
     * Sign members in on the guard people sign in on, and declare the invoice
     * permissions, set before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $config = $app->make('config');

        $config->set('auth.providers.people', ['driver' => 'model', 'model' => Member::class]);
        $config->set('authorization.permission_enums', [InvoicePermission::class]);
    }

    /**
     * A member allowed a refund and a void, with a deny of each guarded by a
     * requirement: the refund's names a level MFA does not know, so the checker
     * throws for it, and the void's is multifactor authentication.
     *
     * @return \Tests\Fixtures\Authorization\Member
     */
    private function member(): Member
    {
        $member = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test', 'password' => self::PASSWORD]);

        $member->attachPolicy(Policy::query()->create([
            'name'     => 'guarded-denies',
            'document' => [
                'statements' => [
                    [
                        'sid'     => 'allow-invoices',
                        'effect'  => 'allow',
                        'actions' => [self::REFUND, self::VOID],
                    ],
                    [
                        'sid'        => 'deny-refund-at-an-unknown-level',
                        'effect'     => 'deny',
                        'actions'    => [self::REFUND],
                        'conditions' => ['authentication_requirement' => ['authentication' => ['assurance_level' => ['min' => 'gold']]]],
                    ],
                    [
                        'sid'        => 'deny-void-once-multifactor',
                        'effect'     => 'deny',
                        'actions'    => [self::VOID],
                        'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
                    ],
                ],
            ],
        ]));

        return $member;
    }

    /**
     * Sign the member in with their password, and return the session's key, as
     * `laravel-authorization`'s subject names it.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(Member $member): string
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $client = new SignInContext(new ClientContext('192.0.2.10', 'iam-tests'));
        $result = $auth->sessions(self::GUARD)->signIn('password', ['email' => $member->email, 'password' => self::PASSWORD], $client);

        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session);

        $key = $result->session->record->getKey();

        self::assertTrue(is_string($key) || is_int($key));

        return (string) $key;
    }
}
