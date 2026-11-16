<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\RoleReach;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Writes the roles a person's provider groups give the identity in the
 * connection's tenant, through `laravel-authorization`'s grant service.
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
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function grant(Identity $identity, string $tenantId, array $instructions): void
    {
        if ($instructions === []) {
            return;
        }

        $reaches = self::reaches($instructions);
        $grantee = self::grantee($identity);
        $tenant  = $this->tenants->toReference($tenantId);
        $service = $this->container->make(GrantService::class);

        foreach ($reaches as $reach) {
            $service->grantRole($grantee, $reach->role, tenant: $tenant, includeSubtree: $reach->includeSubtree);
        }
    }

    /**
     * Make the identity's own roles in the tenant exactly the instructions', a
     * role held live keeping its expiry.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $instructions
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function sync(Identity $identity, string $tenantId, array $instructions): void
    {
        $reaches = self::reaches($instructions);
        $grantee = self::grantee($identity);
        $tenant  = $this->tenants->toReference($tenantId);

        $this->container->make(GrantService::class)->syncRoles($grantee, $reaches, tenant: $tenant);
    }

    /**
     * The groups SSO reports for the result.
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
     * Each instruction's role with its reach, refusing a role given both.
     *
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $instructions
     * @return list<\SineMacula\Laravel\Authorization\Support\RoleReach>
     *
     * @throws \InvalidArgumentException
     */
    private static function reaches(array $instructions): array
    {
        $seen = [];

        foreach ($instructions as $instruction) {
            if (($seen[$instruction->role] ??= $instruction->includeSubtree) !== $instruction->includeSubtree) {
                throw new \InvalidArgumentException(sprintf('The groups grant the role [%s] with both reaches.', $instruction->role));
            }
        }

        return array_map(static fn (GrantInstruction $instruction): RoleReach => RoleReach::of($instruction->role, $instruction->includeSubtree), $instructions);
    }

    /**
     * The identity's Eloquent model, so a role is looked up under its guard.
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
