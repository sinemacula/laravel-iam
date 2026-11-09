<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\SessionMismatchException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for resolving the sign-in MFA names to a session of the
 * guard the MFA application is: by its key whatever the guard holds, where MFA
 * names it, refused for a key that is no session of the identity's on the
 * guard; and the guard's current session, the identity's session when it is the
 * one named, and a refusal by throwing for another of its sessions, for another
 * identity's, for none, and for an application that is no session guard
 * (IAM-8.2). The identity's session SSO's caller names by its key is found of
 * whichever guard. A change to the identity as a whole, which names no guard,
 * goes through the default guard when it holds sessions and otherwise through
 * the first `jwt` guard declared, and is refused when none is.
 *
 * The sessions are real ones, signed in through `laravel-authentication` with a
 * password, against the members' own defaults: the resolution reads only the
 * guard, so none of this package's adapters takes part.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CurrentSession::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class CurrentSessionTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /**
     * The guard's current session is resolved when it is the identity's and the
     * sign-in named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsSessionIsResolvedWhenItIsTheSignInNamed(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $resolved = $this->currentSession()->of($person, self::GUARD, $this->signInReference($session));

        self::assertSame($session->getSessionIdentifier(), $resolved->getSessionIdentifier());
    }

    /**
     * The session a sign-in names is resolved by its key whatever the guard
     * holds: another of the identity's sessions than the guard's, and the
     * identity's session once the guard serves no one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNamedSignInIsResolvedWhateverTheGuardHolds(): void
    {
        $person  = $this->createPerson();
        $other   = $this->signIn($person)->record;
        $current = $this->signInAndActOnSession($person);

        self::assertSame($other->getSessionIdentifier(), $this->currentSession()->named($person, self::GUARD, $this->signInReference($other))->getSessionIdentifier());

        $this->stopActing(self::GUARD);

        self::assertSame($current->getSessionIdentifier(), $this->currentSession()->named($person, self::GUARD, $this->signInReference($current))->getSessionIdentifier());
    }

    /**
     * A sign-in that is no session of the identity's on the guard resolves
     * none: a key no session holds, one that cannot be a key of the session
     * model, another identity's session, a session of another guard, and any
     * sign-in of an identity that holds no sessions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInThatIsNoSessionOfTheIdentitysOnTheGuardResolvesNone(): void
    {
        $person   = $this->createPerson();
        $stranger = $this->signIn($this->createPerson())->record;

        $this->declareGuards(['admin' => $this->sessionGuard(), ...$this->guards()]);

        $elsewhere   = $this->signIn($person, 'admin')->record;
        $sessionless = new class extends User implements Identity, MultiFactorAuthenticatable {
            use HasFactors;
        };

        $sessionless->forceFill(['id' => 1]);

        foreach (['987654', 'not-a-key', $this->signInReference($stranger), $this->signInReference($elsewhere, 'admin')] as $signIn) {
            self::assertUnresolvedSignIn(fn (): mixed => $this->currentSession()->named($person, self::GUARD, $signIn));
        }

        self::assertUnresolvedSignIn(fn (): mixed => $this->currentSession()->named($sessionless, self::GUARD, $this->signInReference($stranger)));

        DB::enableQueryLog();

        self::assertUnresolvedSignIn(fn (): mixed => $this->currentSession()->named($person, self::GUARD, 'not-a-key'));
        self::assertSame([], DB::getQueryLog(), 'A key that cannot be one of the session model\'s is never queried.');
        self::assertUnresolvedGuard('web', fn (): mixed => $this->currentSession()->named($person, 'web', $this->signInReference($elsewhere, 'admin')));
    }

    /**
     * The identity's session a key names is found whichever guard it is of, and
     * nothing else is: another identity's session, a key no session holds, and
     * any key of an identity that holds no sessions are none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentitysOwnSessionIsFoundOfWhicheverGuard(): void
    {
        $person   = $this->createPerson();
        $stranger = $this->signIn($this->createPerson())->record;

        $this->declareGuards(['admin' => $this->sessionGuard(), ...$this->guards()]);

        $elsewhere   = $this->signIn($person, 'admin')->record;
        $sessionless = new class extends User implements Identity {};
        $sessions    = $this->currentSession();

        self::assertSame($elsewhere->getSessionIdentifier(), $sessions->owned($person, $this->signInReference($elsewhere, 'admin'))?->getSessionIdentifier());
        self::assertNull($sessions->owned($person, $this->signInReference($stranger)));
        self::assertNull($sessions->owned($person, '987654'));
        self::assertNull($sessions->owned($sessionless, $this->signInReference($stranger)));
    }

    /**
     * The guard's current session is resolved whichever sign-in it is, when it
     * is the identity's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsCurrentSessionIsResolvedWhicheverSignInItIs(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertSame($session->getSessionIdentifier(), $this->currentSession()->current($person, self::GUARD)->getSessionIdentifier());
        self::assertSame($session->getSessionIdentifier(), $this->currentSession()->held($person, self::GUARD)?->getSessionIdentifier());
    }

    /**
     * Another of the identity's sessions than the guard's is refused as a
     * mismatch, naming the guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherOfTheIdentitysSessionsIsAMismatch(): void
    {
        $person = $this->createPerson();
        $other  = $this->signIn($person)->record;

        $this->signInAndActOnSession($person);

        try {
            $this->currentSession()->of($person, self::GUARD, $this->signInReference($other));

            self::fail('Another of the identity\'s sessions was resolved as the guard\'s.');
        } catch (SessionMismatchException $exception) {
            self::assertSame(self::GUARD, $exception->application);
        }
    }

    /**
     * A guard holding no session resolves none, for a sign-in named or any.
     *
     * @return void
     */
    public function testAGuardHoldingNoSessionResolvesNone(): void
    {
        $person = $this->createPerson();

        self::assertUnresolvedSession(fn (): mixed => $this->currentSession()->of($person, self::GUARD, '1'));
        self::assertUnresolvedSession(fn (): mixed => $this->currentSession()->current($person, self::GUARD));
        self::assertNull($this->currentSession()->held($person, self::GUARD));
    }

    /**
     * A guard acting as the identity on no session, as a trusted bind leaves
     * it, resolves none.
     *
     * @return void
     */
    public function testAGuardActingAsTheIdentityOnNoSessionResolvesNone(): void
    {
        $person = $this->createPerson();

        $this->actingAsIdentity($person, guard: self::GUARD);

        self::assertUnresolvedSession(fn (): mixed => $this->currentSession()->current($person, self::GUARD));
        self::assertNull($this->currentSession()->held($person, self::GUARD));
    }

    /**
     * A guard that stopped acting on the identity's session, as a sign-out
     * leaves it, resolves none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardSignedOutResolvesNone(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->stopActing(self::GUARD);

        self::assertUnresolvedSession(fn (): mixed => $this->currentSession()->of($person, self::GUARD, $this->signInReference($session)));
    }

    /**
     * Another identity's session on the guard is not the identity's, even for
     * the sign-in it names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherIdentitysSessionIsNotResolved(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($this->createPerson());

        self::assertUnresolvedSession(fn (): mixed => $this->currentSession()->of($person, self::GUARD, $this->signInReference($session)));
        self::assertUnresolvedSession(fn (): mixed => $this->currentSession()->current($person, self::GUARD));
        self::assertNull($this->currentSession()->held($person, self::GUARD));
    }

    /**
     * An application that names no guard, a guard that is not
     * `laravel-authentication`'s, or one of its guards that holds no sessions
     * (an `api_key` guard), resolves no session: a misconfiguration, told apart
     * from a guard that holds no session of the identity now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoSessionGuardResolvesNone(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        config()->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people']);

        foreach (['not-a-guard', 'web', 'keys'] as $application) {

            try {
                $this->currentSession()->current($person, $application);

                self::fail(sprintf('A session was resolved on [%s].', $application));
            } catch (UnresolvedReferenceException $exception) {
                self::assertSame(ReferenceKind::GUARD, $exception->kind);
                self::assertSame($application, $exception->application);
                self::assertStringStartsWith(sprintf('The application [%s] is not a laravel-authentication guard', $application), $exception->getMessage());
            }
        }
    }

    /**
     * The identity MFA asks about is `laravel-authentication`'s identity when
     * it is one, and refused when it is not.
     *
     * @return void
     */
    public function testTheIdentityIsLaravelAuthenticationsWhenItIsOne(): void
    {
        $person = $this->createPerson();

        self::assertSame($person, $this->currentSession()->identity($person));

        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        try {
            $this->currentSession()->identity($stranger);

            self::fail('An identity laravel-authentication does not sign in was resolved.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString($stranger::class, $exception->getMessage());
        }
    }

    /**
     * The default guard is the one `Auth::shouldUse()` leaves configured, and
     * none when nothing names one.
     *
     * @return void
     */
    public function testTheDefaultGuardIsTheOneConfigured(): void
    {
        self::assertSame(self::GUARD, $this->currentSession()->defaultGuard());

        config()->set('auth.defaults.guard', 'elsewhere');

        self::assertSame('elsewhere', $this->currentSession()->defaultGuard());

        config()->set('auth.defaults.guard', null);

        self::assertSame('', $this->currentSession()->defaultGuard());
    }

    /**
     * The guard an application names is `laravel-authentication`'s guard of
     * that name, and an application that names none, or names a guard that
     * holds no sessions, is unresolved.
     *
     * @return void
     */
    public function testTheGuardIsTheOneTheApplicationNames(): void
    {
        self::assertSame($this->app?->make('auth')->guard(self::GUARD), $this->currentSession()->guard(self::GUARD));

        config()->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people']);

        foreach (['not-a-guard', 'web', 'keys'] as $application) {
            self::assertUnresolvedGuard($application, fn (): mixed => $this->currentSession()->guard($application));
        }
    }

    /**
     * The caller is the identity the guard serves, and a guard serving no one
     * holds no session of anyone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallerIsTheIdentityTheGuardServes(): void
    {
        self::assertUnresolvedSession(fn (): mixed => $this->currentSession()->caller(self::GUARD));

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $caller = $this->currentSession()->caller(self::GUARD);

        self::assertInstanceOf(Person::class, $caller);
        self::assertTrue($person->is($caller));

        self::assertUnresolvedGuard('not-a-guard', fn (): mixed => $this->currentSession()->caller('not-a-guard'));
    }

    /**
     * The session service is `laravel-authentication`'s for a guard of the
     * `jwt` driver, and an application whose guard holds no sessions, or an
     * auth manager that is not `laravel-authentication`'s, is unresolved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionServiceIsTheJwtGuards(): void
    {
        $person = $this->createPerson();

        $input    = ['email' => $person->email, 'password' => self::PASSWORD];
        $signedIn = $this->currentSession()->sessions(self::GUARD)->signIn('password', $input, new SignInContext(self::client()));

        self::assertTrue($signedIn->isSignedIn());

        config()->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people']);

        foreach (['not-a-guard', 'web', 'keys'] as $application) {
            self::assertUnresolvedGuard($application, fn (): mixed => $this->currentSession()->sessions($application));
        }

        $this->app?->instance('auth', new IlluminateAuthManager($this->app));

        self::assertUnresolvedGuard(self::GUARD, fn (): mixed => $this->currentSession()->sessions(self::GUARD));
    }

    /**
     * A change to the identity as a whole goes through the default guard's
     * session service when the default guard is a `jwt` guard, though another
     * is declared before it: signing in through it binds the default guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentitysSessionServiceIsTheDefaultGuardsWhenItHoldsSessions(): void
    {
        $person = $this->createPerson();

        $this->declareGuards(['admin' => $this->sessionGuard(), ...$this->guards()]);

        self::assertTrue($this->signInThroughTheIdentitysService($person)->isSignedIn());
        self::assertTrue($person->is(Auth::guard(self::GUARD)->user()));
        self::assertNull(Auth::guard('admin')->user());
    }

    /**
     * Where the default guard holds no sessions, a change to the identity as a
     * whole goes through the first `jwt` guard declared, passing over guards of
     * other drivers and entries that are no guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentitysSessionServiceIsTheFirstJwtGuardsWhereTheDefaultHoldsNone(): void
    {
        $person = $this->createPerson();
        $guards = $this->guards();

        config()->set('auth.defaults.guard', 'web');

        $this->declareGuards([
            'web'       => $guards['web'],
            'broken'    => 'not a guard',
            'keys'      => ['driver' => 'api_key', 'provider' => 'people'],
            'admin'     => $this->sessionGuard(),
            self::GUARD => $guards[self::GUARD],
        ]);

        self::assertTrue($this->signInThroughTheIdentitysService($person)->isSignedIn());
        self::assertTrue($person->is(Auth::guard('admin')->user()));
        self::assertNull(Auth::guard(self::GUARD)->user());
    }

    /**
     * The session guards are the guards declared with the `jwt` driver, in the
     * order they are declared, by their names, passing over guards of other
     * drivers and entries that are no guard; with no guards declared there are
     * none.
     *
     * @return void
     */
    public function testTheSessionGuardsAreTheJwtGuardsInTheOrderDeclared(): void
    {
        $guards = $this->guards();

        $this->declareGuards([
            'web'       => $guards['web'],
            'admin'     => $this->sessionGuard(),
            'broken'    => 'not a guard',
            'keys'      => ['driver' => 'api_key', 'provider' => 'people'],
            self::GUARD => $guards[self::GUARD],
            '7'         => $this->sessionGuard(),
        ]);

        self::assertSame(['admin', self::GUARD, '7'], $this->currentSession()->sessionGuards());

        config()->set('auth.guards', 'not guards');

        self::assertSame([], $this->currentSession()->sessionGuards());
    }

    /**
     * A `jwt` guard declared under a number, which the configuration keeps as
     * an integer key, is named by its text.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJwtGuardDeclaredUnderANumberIsNamedByItsText(): void
    {
        $person = $this->createPerson();
        $guards = $this->guards();

        config()->set('auth.defaults.guard', 'web');

        $this->declareGuards(['web' => $guards['web'], '7' => $this->sessionGuard()]);

        self::assertTrue($this->signInThroughTheIdentitysService($person)->isSignedIn());
        self::assertTrue($person->is(Auth::guard('7')->user()));
    }

    /**
     * With no `jwt` guard declared, or no guards at all, nothing names the
     * sessions a change to the identity as a whole would reach: the default
     * guard is refused.
     *
     * @return void
     */
    public function testTheIdentitysSessionServiceIsUnresolvedWithoutAJwtGuard(): void
    {
        $guards = $this->guards();

        config()->set('auth.defaults.guard', 'web');

        $this->declareGuards(['web' => $guards['web'], 'keys' => ['driver' => 'api_key', 'provider' => 'people']]);

        self::assertUnresolvedGuard('web', fn (): mixed => $this->currentSession()->identitySessions());

        config()->set('auth.guards', 'not guards');

        self::assertUnresolvedGuard('web', fn (): mixed => $this->currentSession()->identitySessions());
    }

    /**
     * Assert the resolution refuses an application that names no session guard
     * of `laravel-authentication`'s.
     *
     * @param  string  $application
     * @param  \Closure(): mixed  $resolve
     * @return void
     */
    private static function assertUnresolvedGuard(string $application, \Closure $resolve): void
    {
        try {
            $resolve();

            self::fail(sprintf('A guard was resolved for [%s].', $application));
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);
            self::assertSame($application, $exception->application);
        }
    }

    /**
     * Assert the resolution refuses with no session of the identity on the
     * guard.
     *
     * @param  \Closure(): mixed  $resolve
     * @return void
     */
    private static function assertUnresolvedSession(\Closure $resolve): void
    {
        try {
            $resolve();

            self::fail('A session was resolved where the guard holds none of the identity\'s.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::SESSION, $exception->kind);
            self::assertSame(self::GUARD, $exception->application);
            self::assertStringStartsWith('The guard [api] holds no current session of the identity asked about', $exception->getMessage());
        }
    }

    /**
     * Assert the resolution refuses a sign-in that is no session of the
     * identity's on the guard.
     *
     * @param  \Closure(): mixed  $resolve
     * @return void
     */
    private static function assertUnresolvedSignIn(\Closure $resolve): void
    {
        try {
            $resolve();

            self::fail('A sign-in was resolved that is no session of the identity\'s on the guard.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::SESSION, $exception->kind);
            self::assertSame(self::GUARD, $exception->application);
            self::assertStringStartsWith('The sign-in MFA names is no session of the identity asked about on the guard [api]', $exception->getMessage());
        }
    }

    /**
     * The guards declared now.
     *
     * @return array<string, mixed>
     */
    private function guards(): array
    {
        /** @var array<string, mixed> */
        return config('auth.guards');
    }

    /**
     * Declare exactly these guards, in this order.
     *
     * @param  array<array-key, mixed>  $guards
     * @return void
     */
    private function declareGuards(array $guards): void
    {
        config()->set('auth.guards', $guards);
    }

    /**
     * A `jwt` guard declared as the test's own guard is.
     *
     * @return mixed
     */
    private function sessionGuard(): mixed
    {
        return $this->guards()[self::GUARD];
    }

    /**
     * Sign the person in through the session service a change to the identity
     * as a whole goes through.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInThroughTheIdentitysService(Person $person): SignInResult
    {
        return $this->currentSession()->identitySessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], new SignInContext(self::client()));
    }

    /**
     * Resolve the current session service from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\CurrentSession
     */
    private function currentSession(): CurrentSession
    {
        $current = $this->app?->make(CurrentSession::class);

        self::assertInstanceOf(CurrentSession::class, $current);

        return $current;
    }
}
