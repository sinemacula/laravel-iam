<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\HeldPermission;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference as TenantReference;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\IdentityMemberships;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;

/**
 * Answers audit-log's access policy from the viewer's `audit-log.*` grants,
 * each tenant decided as a check there would decide it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditAccessPolicyAdapter implements AuditAccessPolicy
{
    /**
     * The scope of the trail the viewer may read for the purpose.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        $viewer = $viewer instanceof Reference ? self::model($viewer) : $viewer;

        // Only a model holds grants.
        if (!$viewer instanceof Model) {
            return AccessScope::none();
        }

        $container  = Container::getInstance();
        $subject    = self::subjectOf($viewer);
        $whole      = PermissionCatalogue::audit($purpose);
        $own        = PermissionCatalogue::auditOwn($purpose);
        $byCategory = array_map(static fn (string $category): string => PermissionCatalogue::auditCategory($purpose, $category), PermissionCatalogue::CATEGORIES);
        $categories = array_combine(PermissionCatalogue::CATEGORIES, $byCategory);

        $seen     = [];
        $narrowed = [];
        $ownIn    = [];

        foreach (self::tenants($subject, [$whole, ...$byCategory, $own], $container) as $tenant) {
            $held      = self::heldIn($subject, $tenant, $container);
            $reached   = array_keys(array_intersect($categories, $held));
            $reference = Reference::of(References::TENANT_TYPE, $tenant->id);

            if (in_array($whole, $held, true)) {
                $seen[] = $reference;
            } elseif ($reached !== []) {
                $seen[]     = $reference;
                $narrowed[] = $reached;
            } elseif (in_array($own, $held, true)) {
                $ownIn[] = $reference;
            }
        }

        if ($seen === []) {
            return $ownIn === [] ? AccessScope::none() : AccessScope::tenants(...$ownIn)->onlyAbout(...self::about($subject));
        }

        // A scope holds one list of categories: those every tenant allows.
        return array_reduce($narrowed, static fn (AccessScope $scope, array $reached): AccessScope => $scope->onlyCategories(...$reached), AccessScope::tenants(...$seen));
    }

    /**
     * The tenants to decide the actions in, keyed by id.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<string>  $actions
     * @param  \Illuminate\Container\Container  $container
     * @return array<array-key, \SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    private static function tenants(Subject $subject, array $actions, Container $container): array
    {
        $reviews    = $container->make(AccessReview::class);
        $translator = $container->make(TenantTranslator::class);
        $tenants    = self::memberships($subject, $translator, $container);

        // A subtree grant is decided at its root and in the viewer's tenants.
        foreach ($actions as $action) {
            foreach ($reviews->trustedStream(ReviewQuery::holdings($subject, ReviewScope::everywhere())->forAction($action)) as $row) {
                $root = $row->evidence?->reach->tenant();

                if ($root === null) {
                    continue;
                }

                $tenants[$translator->idOf($root)] = $root;
            }
        }

        return $tenants;
    }

    /**
     * The subject's own tenant and its identity's memberships, keyed by id.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $translator
     * @param  \Illuminate\Container\Container  $container
     * @return array<string, \SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    private static function memberships(Subject $subject, TenantTranslator $translator, Container $container): array
    {
        $ids = $subject->tenant instanceof Tenant ? [IdentifierCoercion::stringify($subject->tenant->getTenantIdentifier())] : [];

        if ($subject->identity instanceof Identity && $container->bound(Memberships::class)) {
            foreach ($container->make(IdentityMemberships::class)->of($subject->identity)->memberships as $membership) {
                $ids[] = $membership->tenantId;
            }
        }

        $tenants = [];

        foreach (array_filter($ids, static fn (?string $id): bool => $id !== null) as $id) {
            $tenants[$id] = $translator->toReference($id);
        }

        return $tenants;
    }

    /**
     * The actions the subject holds unconditionally in the tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \Illuminate\Container\Container  $container
     * @return array<int, string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function heldIn(Subject $subject, TenantReference $tenant, Container $container): array
    {
        $principal = $subject->subject;

        // Where the principal cannot act, only its identity's grants count.
        if ($principal instanceof Principal && !$container->make(TenantAccess::class)->mayActIn($principal, $container->make(TenantReferences::class)->tenant($tenant->id))) {
            $subject = new Subject($principal->getIdentity(), $principal->getIdentity());
        }

        // With no session, a permission needing authentication is not held.
        $held = $container->make(AuthorizationManager::class)->heldPermissionsFor($subject, AuthorizationScope::tenant($tenant));
        $held = array_filter($held, static fn (HeldPermission $permission): bool => $permission->isUnconditional());

        return array_map(static fn (HeldPermission $permission): string => $permission->action, $held);
    }

    /**
     * The viewer as a subject, a principal in its own tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $viewer
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function subjectOf(Model $viewer): Subject
    {
        return $viewer instanceof Principal ? new Subject($viewer, $viewer->getIdentity(), $viewer->getTenant()) : new Subject($viewer, $viewer);
    }

    /**
     * The references the subject's own activity is recorded by.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return array<int, \SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function about(Subject $subject): array
    {
        $models = array_filter([$subject->identity, $subject->subject], static fn (?object $model): bool => $model instanceof Model);

        return array_map(static fn (Model $model): Reference => Reference::to($model), $models);
    }

    /**
     * The model the reference names, through the morph map.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function model(Reference $reference): Model
    {
        $class = Relation::getMorphedModel($reference->type) ?? $reference->type;
        $found = is_a($class, Model::class, true) ? $class::query()->find($reference->id) : null;

        return $found instanceof Model ? $found : throw UnresolvedReferenceException::forIdentityReference($reference->type);
    }
}
