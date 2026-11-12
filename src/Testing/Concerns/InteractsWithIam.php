<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use SineMacula\Laravel\Iam\Testing\CallerSession;
use SineMacula\Laravel\Iam\Testing\CallerSignIn;
use SineMacula\Laravel\Iam\Testing\VerifiedSession;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;

/**
 * Acts as a caller across the suite in a Laravel test, with this package's
 * adapters bound.
 *
 * A person is signed in for real, so every adapter reads the session
 * `laravel-authentication` wrote; a machine is acted as without one.
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
     * Sign the caller in and act as them until the test acts again.
     *
     * A tenant given must resolve through `laravel-authentication`'s
     * `TenantResolver`. A level needs a session signed in with credentials or
     * through SSO, and through SSO a combination policy that classifies the
     * provider's factor. Invalid arguments throw before anything is written; a
     * refused sign-in throws a `LogicException` and rolls back.
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
            $guard   ??= Auth::getDefaultDriver();

            CallerSignIn::assertActable($session, $verified, $scopes);

            $this->actingOnCallerSession($container->make(CallerSignIn::class)->signIn($identity, $principal, $tenantId, $guard, $session, $verified), $verified, $guard);
        }

        if ($tenantId !== null) {
            $this->actingInTenant($container->make(TenantReferences::class)->tenant($tenantId), $guard);
        }

        return $this;
    }

    /**
     * Act on the session, verified now at exactly the level.
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
     * Act on the new session, verified at the level when one is given.
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
