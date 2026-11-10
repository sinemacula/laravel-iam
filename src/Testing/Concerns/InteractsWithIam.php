<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use SineMacula\Laravel\Iam\Testing\CallerSession;
use SineMacula\Laravel\Iam\Testing\CallerSignIn;
use SineMacula\Laravel\Iam\Testing\VerifiedSession;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;

/**
 * Act across the suite in a Laravel test, with this package's adapters bound.
 *
 * `actingAsCaller()` is the one call that arranges a whole caller from plain
 * values: the identity, the principal, the active tenant by its id, the guard,
 * how the session was signed in (`CallerSession`: started, signed in with
 * credentials, or through SSO with SSO's provenance), the level MFA verified it
 * at, and, for a machine, its scopes. A person is signed in for real, as the
 * application signs people in, so every adapter reads the caller from the
 * session `laravel-authentication` wrote, as it reads a real caller's; a
 * machine identity is acted as without a session. `actingOnVerifiedSession()`
 * verifies a session the test already holds instead.
 *
 * With this package's proof store bound, a session's proofs are the ones
 * `laravel-authentication` records and a proof counts only while it names one
 * of the identity's factors, so MFA's `InteractsWithMfa::actingAsVerified()`
 * begins its sign-in and records its proofs through the recorder this package
 * binds (`Testing\VerifiedSignInRecorderAdapter`), which starts the session
 * from a password first factor and steps it up, or completes it, as
 * `actingOnVerifiedSession()` and `actingAsCaller()` do.
 * `actingOnVerifiedSession()` arranges it on a session the test already holds,
 * the way a real step-up does: it acts on the session, as
 * `laravel-authentication`'s `actingOnSession()` does, takes a confirmed factor
 * the session's identity holds (enrolling a fixture one when it holds none) and
 * steps the session up with a proof made with it, then reads the proofs back as
 * MFA's route gate does and throws a `LogicException` unless they evaluate at
 * exactly the level asked for, with additional verification. The session must
 * be a live, active session of a person, signed in as the application signs
 * people in, so it holds its first factor.
 *
 * Acting composes with `laravel-authentication`'s helpers, which this trait
 * brings in: the same context authenticates every request the test then sends
 * through the HTTP kernel, until the test acts again or stops acting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait InteractsWithIam
{
    use InteractsWithAuthenticationContext;

    /**
     * Act as the caller: the identity, as the principal given (or its default
     * one), on the guard given (or the default guard), in the tenant given (or
     * the principal's default), until the test acts again or stops acting.
     *
     * A person is first signed in on the guard as the session says
     * (`CallerSession::started()` when it says nothing), as the application
     * signs people in, and the test acts on the new session, as
     * `actingOnSession()` does. The guard must allow the session's method
     * (`external_provider`, through SSO), and the sign-in must activate. One
     * left pending on a further factor, as the sign-in of a person who already
     * holds a confirmed factor is under an application that then requires one
     * (a person seeded with a factor, or one a level was verified for before),
     * is completed as the person completes it, with a proof of the level's
     * evidence (an authenticator app's when no level is given) made with a
     * confirmed factor of its type the person holds, or one enrolled for them
     * when they hold none; a session `CallerSession::started()` holds no first
     * factor MFA can judge, so it cannot be. One refused, or left pending all
     * the same (on a choice of principal, say), throws a `LogicException`
     * naming the reason, and, for a started session, what to do instead. The
     * tenant is chosen at sign-in, so the session records it as MFA's
     * active-tenant resolver reads it, and the test then acts in it, as
     * `actingInTenant()` does, so `Auth::tenant()` answers it too. A tenant the
     * tenant resolver does not resolve, or tenant access refuses, fails the
     * sign-in, which throws a `LogicException` naming the reason
     * (`tenant_ineligible`), with everything the sign-in wrote rolled back. A
     * tenant given must be resolvable by `laravel-authentication`'s
     * `TenantResolver` even when it is the principal's own, which
     * `laravel-authentication` admits at sign-in without asking a resolver:
     * under the default `ResolveNoTenant`, `UnresolvedReferenceException` is
     * thrown once the person has signed in, and for a machine. With no tenant
     * given, the person acts in the principal's own tenant without a resolver.
     * With a level, the session is then verified at exactly that level with
     * additional verification, as `actingOnVerifiedSession()` verifies it,
     * which needs a first factor MFA can judge: a session signed in with
     * credentials or through SSO. The person then holds a confirmed factor of
     * the level's type, so the same person can be acted as again, signed in
     * with credentials or through SSO, in another tenant or at another level.
     * Through SSO, MFA's default combination policy classifies the provider's
     * first factor at no level, so no level is reached under it; a test of a
     * level through SSO binds the policy the application binds. Without a
     * level, the session holds its first factor alone, and, when the sign-in
     * was left pending, the further proof that completed it.
     *
     * A machine identity signs in to no session: the test acts as it, as
     * `actingAsIdentity()` does, limited to the scopes given (none, `[]`, when
     * no list is given), in the tenant given. A session or a level for a
     * machine, scopes for a person, a level for a session started with no first
     * factor MFA can judge, or the unclassified level, throws an
     * `InvalidArgumentException` before anything is written.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  int|string|null  $tenant
     * @param  ?string  $guard
     * @param  ?\SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $verified
     * @param  ?list<string>  $scopes
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function actingAsCaller(
        Identity $identity,
        ?Principal $principal = null,
        int|string|null $tenant = null,
        ?string $guard = null,
        ?CallerSession $session = null,
        ?AssuranceLevel $verified = null,
        ?array $scopes = null,
    ): static {
        $container = Container::getInstance();
        $tenantId  = $tenant === null ? null : (string) $tenant;

        if ($identity instanceof MachineIdentity) {
            CallerSignIn::assertMachineActable($session, $verified);

            $this->actingAsIdentity($identity, $principal, null, $scopes, $guard);
        } else {
            $session ??= CallerSession::started();
            $guard   ??= $container->make(CurrentSession::class)->defaultGuard();

            CallerSignIn::assertActable($session, $verified, $scopes);

            $this->actingOnCallerSession($container->make(CallerSignIn::class)->signIn($identity, $principal, $tenantId, $guard, $session, $verified), $verified, $guard);
        }

        if ($tenantId !== null) {
            $this->actingInTenant($container->make(TenantReferences::class)->tenant($tenantId), $guard);
        }

        return $this;
    }

    /**
     * Act on the session, on the guard it records (or the guard given, or the
     * default guard), verified now at exactly the level with additional
     * verification.
     *
     * The further proof is made now and the session's first factor when it
     * signed in, so a test of freshness verifies the session and then moves the
     * clock on (`$this->travel(20)->minutes()`), rather than verifying it in
     * the past. The proof is made with a confirmed factor of the level's type
     * the session's identity holds, or one enrolled for it when it holds none:
     * an email factor for AAL1, an authenticator app for AAL2, and a passkey
     * for AAL3, which needs a combination policy that rates a
     * hardware-protected passkey AAL3. The unclassified level is refused with
     * an `InvalidArgumentException` before anything is recorded.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  ?string  $guard
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function actingOnVerifiedSession(EloquentSession&Model $session, AssuranceLevel $level = AssuranceLevel::AAL2, ?string $guard = null): static
    {
        $this->actingOnSession($session, $guard);

        Container::getInstance()->make(VerifiedSession::class)->verify($level);

        return $this;
    }

    /**
     * Act on the caller's new session, verified at the level when one is given.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $verified
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    private function actingOnCallerSession(EloquentSession&Model $session, ?AssuranceLevel $verified, string $guard): void
    {
        if ($verified === null) {
            $this->actingOnSession($session, $guard);

            return;
        }

        $this->actingOnVerifiedSession($session, $verified, $guard);
    }
}
