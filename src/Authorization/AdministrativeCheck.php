<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;

/**
 * Checks one of the members' administrative operations before the application
 * makes it (IAM-6.9, AUTHZ-14.5): the members authorise nothing themselves, so
 * the application calls this, or its own check, before each.
 *
 * The operation is checked through `laravel-authorization` for the subject
 * given, with the member's object as the resource: its type, its id (none for
 * an operation on the type, such as creating a connection) and its tenant, so
 * the decision is made in the object's tenant and a policy can condition on it.
 * A denial throws `laravel-authorization`'s `AuthorizationException`, and a
 * denial for want of a stronger proof whatever this package maps it to
 * (`InsufficientAuthenticationMapping`), so the operation is never made; an
 * allow returns. The check is recorded as any check is: a denial as
 * `authorization.access_denied`, one for want of a stronger proof included,
 * denied with that reason; a subject built for a job or a command carries no
 * session, so such a denial can never be stepped up, and the record is the only
 * evidence of it.
 *
 * The subject is handed in as a resolved `Subject`, never read from the
 * request: the request's own (`Authorization::currentSubject()`, read by the
 * caller), which carries its session, so a requirement on the operation is
 * judged against that session's proofs, or one built for a job or a command. A
 * principal or a model is not taken: `laravel-authorization`'s `for()` would
 * complete it from the request's current subject, its session and its scope,
 * which is the ambient read this check exists to avoid. The `Subject` is
 * decided in the scope it names (its tenant, or the platform for none, and its
 * application), put in place of the request's for the check alone, so a subject
 * built for a job or a command is decided where it acts, and the request's own
 * is decided where the request is. A grant counts for an object of the tenant
 * the subject acts in, or of one below it, and an object of any other tenant is
 * denied (`tenant_scope`) unless a platform-wide grant admits it. The tenant is
 * named by its identifier and resolved through `laravel-authentication`'s
 * tenant resolver (`TenantReferences`); one that names no tenant, or one
 * `laravel-authorization` cannot scope to, is refused
 * (`UnresolvedReferenceException`) rather than checked as the platform's.
 *
 * Stateless (IAM-8.1): `laravel-authorization`'s manager is resolved from the
 * container on every call.
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
     * Check that the subject may make the operation on the member's object, and
     * throw `laravel-authorization`'s denial when it may not: its
     * `AuthorizationException`, or its `InsufficientAuthenticationException`
     * for want of a stronger proof, rethrown from the subject's own scope,
     * which runs the check in a closure.
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
        $manager  = $this->container->make(AuthorizationManager::class)->for($subject);

        self::scopeOf($subject)->within(static fn () => $manager->authorize($action, $resource));
    }

    /**
     * The scope a subject handed in acts in: its own tenant, or the platform
     * for none, and its own application.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Support\AuthorizationScope
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function scopeOf(Subject $subject): AuthorizationScope
    {
        if ($subject->tenant === null) {
            return AuthorizationScope::platform($subject->application);
        }

        try {
            return AuthorizationScope::tenant(new Reference(...TenantScope::extractTenantPair($subject->tenant)), $subject->application);
        } catch (InvalidTenantException) {
            throw UnresolvedReferenceException::forTenantIdentifier();
        }
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
