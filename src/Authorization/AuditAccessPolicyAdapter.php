<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
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
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\IdentityMemberships;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;

/**
 * Audit-log's access policy, answered from `laravel-authorization`'s grants
 * (IAM-6.10): what of the trail a viewer may read, count, export or verify.
 *
 * Each purpose has its own permissions in this package's catalogue
 * (`PermissionCatalogue`), so a viewer can page through entries while being
 * denied export: `audit-log.{purpose}` reaches every category,
 * `audit-log.{purpose}.{category}` one of the suite's categories (`security`,
 * `access_management`, `audit`), and `audit-log.{purpose}.own` only the
 * viewer's own activity. Which of them the viewer holds, and where, is listed
 * through `laravel-authorization`'s `permissionsFor()`, the introspection that
 * decides each action exactly as a check would and records no decision, once
 * for each tenant the viewer may hold grants in: the viewer's own tenant and,
 * while the application binds its memberships (`Contracts\Memberships`), each
 * tenant it is a member of. A principal is decided as itself in another of
 * those tenants only where `laravel-authentication`'s tenant access
 * (`TenantAccess::mayActIn()`) lets it act there, since no check lets it use a
 * grant where it cannot act; elsewhere only its identity's grants are listed,
 * which hold across every principal the identity has. A platform-wide grant
 * counts in each of those tenants as any grant there does, but is never read on
 * its own: a listing on the platform sees none of a tenant's denies, guardrails
 * or boundaries, so it would show a tenant's trail that tenant's own decision
 * refuses. A viewer with no tenant to decide in therefore sees nothing, and
 * reading the whole trail, the platform's own entries among it, takes the
 * application's own policy, bound in place of this one.
 *
 * The grants become one `AccessScope`, never wider than any of them:
 *
 * - the tenants where the viewer holds the purpose (`tenants()`), in the
 *   categories every one of them allows: a tenant whose grant reaches some
 *   categories narrows them for every tenant, since a scope holds one list of
 *   categories, and tenants that share no category see nothing;
 * - otherwise the viewer's own activity (`onlyAbout()`, as the actor or the
 *   subject of an entry, by its identity and its principal) in the tenants
 *   where it holds `.own`;
 * - otherwise nothing (`none()`).
 *
 * It never uses `all()`, `withTenantless()` nor `exceptCategories()`: an entry
 * with no tenant may be about any tenant's people, and a category excepted
 * leaves every other category, the application's own among them, seen; either
 * would show more than a grant named. An empty list of tenants, categories or
 * references sees nothing, and more than audit-log's limits (100 tenants, 50
 * categories, 100 references) is refused by audit-log's scope rather than
 * truncated: a throw is a failed read.
 *
 * The viewer's own tenant is named by its identifier, as the memberships name
 * theirs; one whose identifier is no text or number cannot be named, and only
 * its memberships are read. The viewer is a model, or a reference audit-log
 * names it by, read through the morph map; one that names nobody is refused
 * (`UnresolvedReferenceException`). A principal of `laravel-authentication` is
 * decided as itself, for its identity, in its tenant; any other model as
 * itself.
 *
 * The policy is told who reads and why, never how they signed in, so it cannot
 * tell whether an authentication requirement is met, and treats a permission a
 * requirement guards as not held in that tenant. The subject carries a session
 * key that names no session (`UNJUDGED_SESSION`), which this package's
 * requirement checker refuses by throwing, so `laravel-authorization` reads
 * every requirement as undecidable: an allow it guards does not apply, and a
 * deny it guards does. With no session at all, a requirement would be unmet
 * without asking, and a deny it guards would not apply, listing an action the
 * reader's own session might be refused. Freshness for reading the trail
 * belongs on the route that reads it, enforced before audit-log is asked. Nor
 * is the policy told the scopes of the reader's credential, so the subject says
 * them as those of a subject naming no credential
 * (`SessionPolicySourceAdapter::withoutCredential()`): no cap for a person and
 * none granted for a machine, as before; left unsaid, the session key would be
 * taken for a session to look up, and every reader would be allowed nothing.
 *
 * It never reads the entries table, keeps nothing between calls and is bound as
 * a singleton (IAM-8.1): `laravel-authorization`'s manager, the memberships and
 * the tenants are resolved from the application current on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditAccessPolicyAdapter implements AuditAccessPolicy
{
    /** @var string The session key the viewer is decided on: it holds a colon, so no session key equals it, and no requirement can be judged for it. */
    private const string UNJUDGED_SESSION = 'iam:audit-access';

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
    public function scope(Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        $container = Container::getInstance();
        $subject   = self::subjectOf($viewer instanceof Reference ? self::model($viewer) : $viewer);
        $manager   = $container->make(AuthorizationManager::class);
        $holds     = static fn (Subject $decided, AuthorizableTenant|Model $tenant): array => self::held(
            $manager->permissionsFor($decided, AuthorizationScope::tenant($tenant)),
            $purpose,
        );

        $reached = [];
        $own     = [];

        foreach (self::candidates($subject, $container) as $tenantId => $tenant) {
            $held = $holds(self::decidedIn($subject, $tenant, $container), $tenant);

            if ($held['whole'] || $held['categories'] !== []) {
                $reached[$tenantId] = $held;
            } elseif ($held['own']) {
                $own[] = self::tenantReference($tenantId);
            }
        }

        return match (true) {
            $reached !== [] => self::tenants($reached),
            $own     !== [] => AccessScope::tenants(...$own)->onlyAbout(...self::about($subject)),
            default         => AccessScope::none(),
        };
    }

    /**
     * What of the purpose's permissions the listing holds: the whole purpose,
     * the suite's categories it reaches, and the viewer's own activity.
     *
     * @param  list<string>  $listed
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return array{whole: bool, categories: list<string>, own: bool}
     */
    private static function held(array $listed, ReadPurpose $purpose): array
    {
        $reaches    = static fn (string $category): bool => in_array(PermissionCatalogue::auditCategory($purpose, $category), $listed, true);
        $categories = array_filter(PermissionCatalogue::CATEGORIES, $reaches);

        return [
            'whole'      => in_array(PermissionCatalogue::audit($purpose), $listed, true),
            'categories' => array_values($categories),
            'own'        => in_array(PermissionCatalogue::auditOwn($purpose), $listed, true),
        ];
    }

    /**
     * The scope narrowed to the categories held, unless the whole purpose is.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  array{whole: bool, categories: list<string>, own: bool}  $held
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     *
     * @throws \InvalidArgumentException
     */
    private static function narrowed(AccessScope $scope, array $held): AccessScope
    {
        return $held['whole'] ? $scope : $scope->onlyCategories(...$held['categories']);
    }

    /**
     * The scope of the tenants reached, in the categories every one of them
     * allows.
     *
     * @param  non-empty-array<string, array{whole: bool, categories: list<string>, own: bool}>  $reached
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     *
     * @throws \InvalidArgumentException
     */
    private static function tenants(array $reached): AccessScope
    {
        $scope = AccessScope::tenants(...array_map(self::tenantReference(...), array_keys($reached)));

        foreach ($reached as $held) {
            $scope = self::narrowed($scope, $held);
        }

        return $scope;
    }

    /**
     * The tenants the viewer may hold grants in, by identifier: its own and,
     * while the application binds its memberships, each it is a member of.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \Illuminate\Container\Container  $container
     * @return array<array-key, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    private static function candidates(Subject $subject, Container $container): array
    {
        $tenants = [];

        $own = $subject->tenant instanceof Tenant ? IdentifierCoercion::stringify($subject->tenant->getTenantIdentifier()) : null;

        if ($own !== null) {
            $tenants[$own] = self::scopable($subject->tenant, $own);
        }

        $identity = $subject->identity;

        if (!$identity instanceof Identity || !TenancyContracts::hasMemberships($container, $container->make(Repository::class))) {
            return $tenants;
        }

        $references = $container->make(TenantReferences::class);

        foreach ($container->make(IdentityMemberships::class)->of($identity)->memberships as $membership) {
            if ($membership->tenantId === null || isset($tenants[$membership->tenantId])) {
                continue;
            }

            $tenants[$membership->tenantId] = self::scopable($references->tenant($membership->tenantId), $membership->tenantId);
        }

        return $tenants;
    }

    /**
     * The subject the viewer is decided as in the tenant: itself in its own
     * tenant, and in another wherever it is no principal or
     * `laravel-authentication`'s tenant access lets the principal act there.
     * Otherwise its identity alone: `laravel-authorization` would move the
     * principal into the tenant as it is, so a grant made to it there would
     * count, though no check lets it act there; an identity's grants hold
     * across every principal it has, the one it acts as there among them.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  object  $tenant
     * @param  \Illuminate\Container\Container  $container
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function decidedIn(Subject $subject, object $tenant, Container $container): Subject
    {
        $principal = $subject->subject;

        if (!$principal instanceof Principal || $tenant === $subject->tenant) {
            return $subject;
        }

        $mayAct = $tenant instanceof Tenant && $container->make(TenantAccess::class)->mayActIn($principal, $tenant);

        return $mayAct ? $subject : new Subject($principal->getIdentity(), $principal->getIdentity(), $tenant, session: $subject->session, scopes: $subject->scopes);
    }

    /**
     * The tenant as `laravel-authorization` scopes a listing to it: a model or
     * a tenant of its own; any other cannot be, and is refused.
     *
     * @param  ?object  $tenant
     * @param  string  $tenantId
     * @return \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function scopable(?object $tenant, string $tenantId): AuthorizableTenant|Model
    {
        return $tenant instanceof Model || $tenant instanceof AuthorizableTenant ? $tenant : throw UnresolvedReferenceException::forTenant($tenantId);
    }

    /**
     * The reference audit-log names the tenant by: its identifier, under the
     * one tenant type every member's records use.
     *
     * @param  int|string  $tenantId
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function tenantReference(int|string $tenantId): Reference
    {
        return Reference::of(References::TENANT_TYPE, (string) $tenantId);
    }

    /**
     * The references the viewer's own activity is recorded by: its identity and
     * its principal, each a model; audit-log's scope holds one that is both
     * once.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function about(Subject $subject): array
    {
        $models = array_values(array_filter([$subject->identity, $subject->subject], static fn (?object $model): bool => $model instanceof Model));

        return array_map(static fn (Model $model): Reference => Reference::to($model), $models);
    }

    /**
     * The subject the viewer is decided as: a principal as itself, for its
     * identity, in its tenant; any other model as itself; on a session no
     * requirement can be judged for, with the scopes of a viewer whose
     * credential the policy is never told: no cap for a person, and none
     * granted for a machine, as the session policy source answers a subject
     * naming no credential, so the session key is never taken for one to look
     * up.
     *
     * @param  object  $viewer
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \LogicException
     */
    private static function subjectOf(object $viewer): Subject
    {
        $identity = $viewer instanceof Principal ? $viewer->getIdentity() : $viewer;
        $tenant   = $viewer instanceof Principal ? $viewer->getTenant() : null;

        return new Subject($viewer, $identity, $tenant, session: self::UNJUDGED_SESSION, scopes: SessionPolicySourceAdapter::withoutCredential($viewer, $identity));
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
