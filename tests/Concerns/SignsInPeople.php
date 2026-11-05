<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use Tests\Fixtures\Models\Person;

/**
 * Creates people and signs them in through `laravel-authentication`'s public
 * session service, as a real sign-in does, so each session holds the
 * first-factor proof (on the `password` channel) that step-up,
 * reauthentication, freshness and MFA's requirement check read.
 *
 * A session the test makes itself holds no proof, so every adapter test starts
 * its sessions here. Signing in binds the guard to the new session for the rest
 * of the request, as `laravel-authentication` does; acting on a session binds
 * the guard to it as a later bearer request for it would, until the test acts
 * again or stops acting. The tables come from `MigratesMembers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait SignsInPeople
{
    use InteractsWithAuthenticationContext;

    /**
     * Create a person who signs in with the tests' password, under the email
     * address given or one no other person has.
     *
     * @param  ?string  $email
     * @return \Tests\Fixtures\Models\Person
     */
    protected function createPerson(?string $email = null): Person
    {
        return Person::query()->create([
            'name'     => 'Ada Lovelace',
            'email'    => $email ?? 'person-' . Str::lower((string) Str::ulid()) . '@example.test',
            'password' => self::PASSWORD,
        ]);
    }

    /**
     * Sign the person in with their password on the guard, and return the
     * result: signed in, or pending while a further factor or a choice is
     * outstanding.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    protected function attemptSignIn(Person $person, string $guard = self::GUARD): SignInResult
    {
        return $this->sessions($guard)->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD]);
    }

    /**
     * Sign the person in with their password on the guard, failing the test
     * unless the session starts active, and return it with its tokens.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    protected function signIn(Person $person, string $guard = self::GUARD): SignedInSession
    {
        $result = $this->attemptSignIn($person, $guard);

        if (!$result->isSignedIn() || $result->session === null) {
            self::fail(sprintf('The person did not sign in: [%s].', $result->reason->value ?? $result->status->value));
        }

        return $result->session;
    }

    /**
     * Sign the person in on the guard and act on the new session, as a bearer
     * request for it would, and return the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $guard
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    protected function signInAndActOnSession(Person $person, string $guard = self::GUARD): EloquentSession&Model
    {
        $session = $this->signIn($person, $guard)->record;

        $this->actingOnSession($session, $guard);

        return $session;
    }

    /**
     * The counting proofs the session records, newest first, as
     * `laravel-authentication` answers them for the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $guard
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \Throwable
     */
    protected function proofsOf(Session $session, string $guard = self::GUARD): array
    {
        return $this->sessions($guard)->proofs($session, limit: RequirementSubject::MAX_LIMIT);
    }

    /**
     * The first-factor proof the session signed in with, as
     * `laravel-authentication` answers it for the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \Throwable
     */
    protected function firstFactorOf(Session $session, string $guard = self::GUARD): ?RecordedProof
    {
        return $this->sessions($guard)->firstFactor($session);
    }

    /**
     * The reference MFA names the session's sign-in by.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $guard
     * @return string
     */
    protected function signInReference(Session $session, string $guard = self::GUARD): string
    {
        return SignIn::reference($session, $guard);
    }

    /**
     * `laravel-authentication`'s session service for the guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    protected function sessions(string $guard = self::GUARD): SessionService
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return $auth->sessions($guard);
    }
}
