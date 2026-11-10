<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\ClientContext as MfaClientContext;
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
 * Every action is handed its client as a plain value, as an application's
 * controller hands it on: `client()` for `laravel-authentication`, and
 * `callerOf()` for MFA's self-service actions, the person as an active caller
 * on the guard, or `servedCaller()`, the caller as MFA reads one from a request
 * served now (`CallerContext::fromRequest()`), whoever the guard serves; and
 * `requestCallerOf()` for this package's SSO calls, the person as
 * `laravel-authentication`'s caller of a request, holding the session the guard
 * serves now, as `Auth::caller()` reads it where an application reads the
 * request.
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

    /** @var string The IP address the tests' client comes from. */
    protected const string CLIENT_IP = '192.0.2.10';

    /** @var string The user agent the tests' client sends. */
    protected const string CLIENT_AGENT = 'iam-tests';

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
        return $this->sessions($guard)->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], new SignInContext(self::client()));
    }

    /**
     * The client the tests' actions are served to, as `laravel-authentication`
     * is handed it.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    protected static function client(): ClientContext
    {
        return new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT);
    }

    /**
     * The person as MFA's active caller on the guard, served to the tests'
     * client.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $guard
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    protected static function callerOf(Person $person, string $guard = self::GUARD): CallerContext
    {
        return CallerContext::forIdentity($person, $guard, new MfaClientContext(self::CLIENT_IP, self::CLIENT_AGENT));
    }

    /**
     * The identity as `laravel-authentication`'s caller of a request on the
     * guard, its access credential holding the session the guard serves now, as
     * `Auth::caller()` reads it: whoever's session that is, or none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    protected function requestCallerOf(Identity $identity, string $guard = self::GUARD): Caller
    {
        $session = $this->app?->make(CurrentSession::class)->guard($guard)->session();

        return new Caller($guard, CallerCredential::ACCESS, $identity, null, null, $session);
    }

    /**
     * MFA's caller as it reads one from the request given, or from a request
     * carrying nothing: the pending session its credential names, or the person
     * the default guard serves now, or nobody.
     *
     * @param  ?\Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    protected static function servedCaller(?Request $request = null): CallerContext
    {
        return CallerContext::fromRequest($request ?? Request::create('/'));
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
     * The context a tenant authentication policy is asked with about the
     * session acting in the tenant, or the sign-in about to write one (no
     * session), on the guard, built through its public constructor: the
     * connection the session was established through is the one the closure
     * names, found only once the policy asks.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Closure(): ?string  $connectionId
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext
     */
    protected static function tenantPolicyContext(
        Identity $identity,
        Principal $principal,
        Tenant $tenant,
        ?Session $session,
        \Closure $connectionId,
        string $guard = self::GUARD,
    ): TenantPolicyContext {
        return new TenantPolicyContext($guard, $identity, $principal, $tenant, $session, $connectionId);
    }

    /**
     * The connection the session was established through, as its recorded
     * provenance names it, read through `laravel-authentication`'s public
     * reader of a session's provenance for the guard; `null` for a session no
     * provider established.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $guard
     * @return ?string
     *
     * @throws \Throwable
     */
    protected function recordedConnectionOf(Session $session, string $guard = self::GUARD): ?string
    {
        return $this->sessions($guard)->provenance($session)?->connectionId;
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
