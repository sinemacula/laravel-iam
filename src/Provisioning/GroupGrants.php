<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Writes the grants a person's provider groups give them (IAM-7.2), through
 * `laravel-authorization`'s grant service, as trusted system work: no acting
 * principal decides them, and each grant row records none.
 *
 * Every grant is of a role to the identity itself, which holds across every
 * principal of it, in the connection's tenant, named to `laravel-authorization`
 * through `laravel-authentication`'s tenant resolver (`TenantTranslator`), and
 * in every application. `grant()` adds the instructions' roles, for a person
 * just provisioned, who holds nothing yet; `sync()` makes the identity's own
 * roles in the tenant exactly the instructions' (`syncRoles()`), revoking every
 * other role the identity itself holds there, then sets each one's reach, so a
 * re-sync never leaves a role the groups no longer give, nor grants one they do
 * not. Roles granted to the identity's principals, in other tenants or
 * platform-wide are never touched.
 *
 * Each call runs in a savepoint of the caller's transaction on the storage
 * connection, which `authorization.connection` must name (this package aligns
 * it): a grant on another connection would commit apart from the provisioning
 * or the sign-in. A grant that widens the identity's scope reports it to SSO
 * first, through the grant hook (`Authorization\GrantHookAdapter`). Inside the
 * caller's transaction `laravel-authorization` never retries a conflict with
 * its hook, but throws it for the caller's own retry. A role name it does not
 * find, an identity that is no Eloquent model, a tenant that cannot be
 * resolved, and whatever the hook or the service throws, propagate, so the
 * caller's transaction rolls back. It reads no request, nor the current user,
 * and keeps nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GroupGrants
{
    /** @var string The attribute SSO reports a person's groups in. */
    public const string GROUPS = 'groups';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Resolves `laravel-authorization`'s grant service on every call. */
        private Container $container,

        /** Names the connection's tenant as `laravel-authorization` names it. */
        private TenantTranslator $tenants,
    ) {}

    /**
     * Grant the identity each instruction's role in the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $instructions
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function grant(Identity $identity, string $tenantId, array $instructions): void
    {
        if ($instructions === []) {
            return;
        }

        $grantee = self::grantee($identity);
        $tenant  = $this->tenants->toReference($tenantId);
        $service = $this->container->make(GrantService::class);

        foreach ($instructions as $instruction) {
            $service->grantRole($grantee, $instruction->role, tenant: $tenant, includeSubtree: $instruction->includeSubtree);
        }
    }

    /**
     * Make the identity's own roles in the tenant exactly the instructions'.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $instructions
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function sync(Identity $identity, string $tenantId, array $instructions): void
    {
        $grantee = self::grantee($identity);
        $tenant  = $this->tenants->toReference($tenantId);
        $service = $this->container->make(GrantService::class);
        $roles   = array_map(static fn (GrantInstruction $instruction): string => $instruction->role, $instructions);

        $service->syncRoles($grantee, $roles, tenant: $tenant, includeSubtree: false);

        foreach ($instructions as $instruction) {
            $service->grantRole($grantee, $instruction->role, tenant: $tenant, includeSubtree: $instruction->includeSubtree);
        }
    }

    /**
     * The groups SSO reports for the result, each as the provider sent it: a
     * list, a single group, or none when the connection maps none.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return list<string>
     */
    public static function groupsOf(#[\SensitiveParameter] VerifiedResult $result): array
    {
        $groups = $result->attributes[self::GROUPS] ?? [];

        return is_string($groups) ? [$groups] : $groups;
    }

    /**
     * The identity as `laravel-authorization`'s grantee: the Eloquent model
     * itself, so a role is looked up under its own guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function grantee(Identity $identity): Model
    {
        return $identity instanceof Model ? $identity : throw UnresolvedReferenceException::forIdentity($identity::class);
    }
}
