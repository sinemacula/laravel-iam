<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;

/**
 * Checks a member's administrative operation through `laravel-authorization`
 * for a resolved subject, with the member's object as the resource.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class AdministrativeCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantReferences  $tenants
     */
    public function __construct(

        /** Resolves `laravel-authorization`'s manager on every call. */
        private Container $container,

        /** Resolves the tenant an identifier names. */
        private TenantReferences $tenants,
    ) {}

    /**
     * Throw `laravel-authorization`'s denial unless the subject may operate.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation|string  $operation
     * @param  string  $resourceType
     * @param  ?string  $resourceId
     * @param  ?string  $tenantId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function authorize(Subject $subject, AdministrativeOperation|string $operation, string $resourceType, ?string $resourceId = null, ?string $tenantId = null): void
    {
        $tenant   = $tenantId   === null ? null : $this->tenant($tenantId);
        $resource = $resourceId === null ? ResourceReference::type($resourceType, $tenant) : ResourceReference::record($resourceType, $resourceId, $tenant);
        $action   = $operation instanceof AdministrativeOperation ? $operation->value : $operation;

        $this->container->make(AuthorizationManager::class)->for(self::decidedWhereItActs($subject))->authorize($action, $resource);
    }

    /**
     * The subject, marked as acting on the platform when it names no tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function decidedWhereItActs(Subject $subject): Subject
    {
        // Unmarked, `for()` would decide it in the request's tenant.
        if ($subject->tenant === null) {
            return new Subject($subject->subject, $subject->identity, null, $subject->application, $subject->guard, $subject->session, $subject->scopes, platform: true);
        }

        try {
            TenantScope::extractTenantPair($subject->tenant);
        } catch (InvalidTenantException) {
            throw UnresolvedReferenceException::forTenantIdentifier();
        }

        return $subject;
    }

    /**
     * The reference `laravel-authorization` names the tenant by.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function tenant(string $tenantId): Reference
    {
        try {
            return new Reference(...TenantScope::extractTenantPair($this->tenants->tenant($tenantId)));
        } catch (InvalidTenantException) {
            throw UnresolvedReferenceException::forTenant($tenantId);
        }
    }
}
