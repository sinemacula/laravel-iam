<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Protocols\DriverScope;

/**
 * Flushes every member's request state, so nothing one request or job bound
 * reaches the next in a long-lived process (IAM-11.3).
 *
 * It resets every `laravel-authentication` guard already resolved to the
 * current request, creating none, once the auth manager holds the application
 * being reset, drops the callers `laravel-authentication` keeps on the current
 * request (`Auth::caller()`), flushes the session already resolved, where
 * `laravel-mfa`'s default proof store keeps its proofs, and forgets the scoped
 * instances the members keep their request state in: `laravel-authentication`'s
 * rehashing, kept sessions, required work and watched sessions, `laravel-sso`'s
 * scoped seams, and `laravel-authorization`'s resolved tenant, resolution
 * cache, last decision, policy evaluator, session scopes, check context
 * factory, the abilities its Gate hook answers, the schema its query scope
 * reads and its manager, and every scoped default behind its contracts, held
 * under its own `authorization.default:` keys, and this package's scoped
 * adapters, held under its own `iam.scoped:` keys, what its previews know and
 * the console subject resolver its explanations resolve through among them.
 * Authorization's own resets (its last decision store, its resolution cache and
 * its tenant scope) are not called: every one of them clears state held in a
 * scoped instance this forgets, and its explanations keep nothing beyond the
 * check that asks for one. The adapters this package binds over its seams keep
 * nothing at all; the subject resolver, application access and the tenant tree
 * are scoped all the same, under `iam.scoped:`, the resolver so that
 * `laravel-authorization` keeps the tenant it resolved for one unit of work and
 * the tree so that it keeps the tenant chain it read, since it keys that memo
 * by the tree instance, and forgotten with the rest. It then clears the roots
 * Laravel's facades keep, as the queue worker does once it forgets its scoped
 * instances and Octane does as it switches application:
 * `laravel-authorization`'s `Authorization` facade keeps the manager it first
 * resolved, and the manager holds its last decision, evaluator and resolvers,
 * so through the facade a later unit of work would otherwise keep reading the
 * first one's. It registers itself for Octane's workers and requests and the
 * queue's jobs, and is safe to call by hand in any other long-lived process,
 * between its units of work.
 *
 * Before it forgets anything, `reset()` releases the work this package held for
 * a commit that finished without running it, a commit callback having failed
 * (`AfterConnectionCommits::settle()`), on every connection with no transaction
 * open, which forgetting its record would otherwise drop.
 *
 * Only the suite's own scoped instances are forgotten, never every one the
 * container holds: Laravel keeps a command's or a job's `Context` and its
 * deferred callbacks in scoped instances, and `laravel-audit-log` its execution
 * frames, which it enters and leaves itself as each request, command and job
 * starts and ends. A reset called between units of work in a command would
 * otherwise drop the callbacks queued with `defer()` before they ran, the
 * command's `Context` and the audit trail's command frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class WorkerReset
{
    /** @var string The prefix of the keys `laravel-authorization` holds the scoped defaults behind its resolvers under. */
    private const string AUTHORIZATION_DEFAULT = 'authorization.default:';

    /** @var string The pattern of the request attributes `laravel-authentication` keeps each request's callers under (`CallerCredentials`): its prefix, followed by the credential, the guard and the action. */
    private const string CALLER_MEMO = '/^authentication\.caller\./';

    /** @var list<string> The scoped bindings `laravel-authentication`, `laravel-sso` and `laravel-authorization` keep request state in; authorization's scoped defaults and this package's scoped adapters are found by the prefix of their keys. */
    private const array SCOPED_STATE = [
        Rehashing::class,
        KeptSessions::class,
        RequiredWork::class,
        WatchedSessions::class,
        SingleUseStore::class,
        SecretEncrypter::class,
        Fetcher::class,
        AttemptLimiter::class,
        DnsResolver::class,
        Enforcement::class,
        EndpointResolver::class,
        HandoffIssuer::class,
        DriverScope::class,
        ResolvedTenant::class,
        ResolutionCache::class,
        LastDecisionStore::class,
        PolicyEvaluator::class,
        SessionScopes::class,
        CheckContextFactory::class,
        DeclaredAbilities::class,
        SchemaInspector::class,
        Previewing::class,
        'authorization',
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The application whose request state is flushed. */
        private Container $container,
    ) {}

    /**
     * Release the work held for a commit that has finished, then flush every
     * member's request state: the guards, the session, the scoped instances the
     * members keep it in and the facades' roots resolved from them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function reset(): void
    {
        $this->container->make(AfterConnectionCommits::class)->settle();
        $this->forgetMemberState();
        $this->forgetScopedState();
    }

    /**
     * Flush the request state the members keep outside scoped instances, and
     * leave every scoped instance where it is.
     *
     * A queue worker forgets the scoped instances itself before it fetches each
     * job, and Octane clones each request's sandbox from an application whose
     * scoped instances it forgets once each operation ends; by the time a job's
     * or a request's listeners run, others among them have already filled
     * scoped instances for it (the audit log's job frame, the request's
     * `Context`), which a second flush would discard.
     *
     * Every `laravel-authentication` guard already resolved is reset to the
     * current request, and the session already resolved is flushed:
     * `laravel-mfa`'s default proof store keeps its proofs there, and a
     * worker's session lives in memory for as long as the worker does, so a job
     * would otherwise pass a check on the proofs an earlier job made for the
     * same person. The callers `laravel-authentication` keeps on the current
     * request's attributes (`authentication.caller.`, then the credential, the
     * guard and the action) are dropped too: it reads `Auth::caller()` once per
     * request and keeps the answer there, and every job a worker runs shares
     * one request, so a job would otherwise be decided about the first job's
     * caller, with its grants, tenant and session, whoever its guards hold now
     * (`Authorization\SubjectResolverAdapter`). Neither the auth manager, the
     * request nor the session is built when nothing has resolved it, since none
     * can hold state then, and an `auth`, `request` or `session.store` binding
     * the application made that is not the member's manager, a request or a
     * session is left alone. This runs only between units of work (never for a
     * `sync` job, which shares the session and the request of the request that
     * dispatched it), where no session has started for the next one yet.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function forgetMemberState(): void
    {
        $this->forgetGuardState();
        $this->forgetCallers();
        $this->flushSession();
    }

    /**
     * Forget the scoped instances the members keep their request state in, when
     * the container can forget an instance, so the next unit of work builds its
     * own; every other scoped instance is kept. The facades' resolved roots are
     * then cleared, so a facade resolves its root afresh too.
     *
     * Only a seam the container still keeps as scoped is forgotten, as
     * Laravel's own `forgetScopedInstances()` forgets only those. An instance
     * or a singleton the application bound over a member's seam before the
     * member registered, which the member's `scopedIf()` then left alone, is
     * the application's, and forgetting it would drop it for good, or rebuild
     * it. The container lists its scoped abstracts only in a protected
     * property, read here as `MemberDefaults` reads the binding table. That
     * list also holds the closure itself for a binding scoped by its closure's
     * return type, which is never the suite's: every abstract the suite keeps
     * request state under is a string, so such an entry is passed over.
     *
     * A facade keeps the root it first resolved in a static cache of its own,
     * outside the container, which forgetting the instance leaves holding it:
     * `laravel-authorization`'s `Authorization` facade would keep returning the
     * manager built for the first unit of work, with that unit's last decision,
     * evaluator and resolvers. Every root is cleared, as the queue worker
     * clears them once it forgets its scoped instances and Octane as it
     * switches application, not only those under the keys forgotten: a facade
     * may name a member's state by an alias (`AuthorizationManager` for
     * `authorization`), or be a real-time facade, and every root cleared
     * resolves again from the container, so a facade over anything the reset
     * kept still returns the same instance. Octane's requests and the queue's
     * jobs reset with `forgetMemberState()` alone, never coming here, since
     * both clear the roots themselves.
     *
     * This package calls it once more as the application finishes booting, when
     * it binds its adapters again over the defaults of a
     * `laravel-authorization` another provider registered from its `boot()`:
     * whatever was resolved from those defaults meanwhile (the manager, with
     * the default subject resolver, session cap and check context factory it
     * holds, the tenant it resolved) is forgotten, so the next resolution holds
     * the adapters (`IamServiceProvider`).
     *
     * @return void
     */
    public function forgetScopedState(): void
    {
        if (!$this->container instanceof IlluminateContainer) {
            return;
        }

        foreach (self::scopedAbstracts($this->container) as $abstract) {

            if (!is_string($abstract) || !self::isSuiteState($abstract)) {
                continue;
            }

            $this->container->forgetInstance($abstract);
        }

        Facade::clearResolvedInstances();
    }

    /**
     * Reset every `laravel-authentication` guard already resolved to the
     * current request, when the auth manager is resolved and is that member's.
     *
     * The manager is pointed at the application being reset first, as Octane's
     * own `FlushAuthenticationState` points it at each request's sandbox: the
     * manager is shared across a worker's requests and resolves the request
     * from the application it holds, which, until Octane's listener has run for
     * this request, is the last request's sandbox, already flushed. Octane
     * registers its listeners as its provider boots, so whether they run before
     * or after this package's follows the providers' boot order, which the
     * reset does not rely on.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function forgetGuardState(): void
    {
        if (!$this->container->resolved('auth')) {
            return;
        }

        $auth = $this->resolve('auth');

        // An application may bind another manager to `auth`, whatever the
        // installed members bind.
        if (!$auth instanceof AuthManager) {
            return;
        }

        // The manager may still hold another application: under Octane, the
        // last request's sandbox, which Octane has flushed, until its own
        // listener moves the manager on, whichever order the two run in.
        if ($this->container instanceof Application) {
            $auth->setApplication($this->container);
        }

        $auth->forgetGuardState();
    }

    /**
     * Drop the callers `laravel-authentication` keeps on the current request's
     * attributes, when the request is resolved and is one, so the next unit of
     * work reads its own caller from the guards as they stand then. Every other
     * attribute is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function forgetCallers(): void
    {
        if (!$this->container->resolved('request')) {
            return;
        }

        $request = $this->resolve('request');

        // An application may bind something other than a request to `request`,
        // which keeps no callers.
        if (!$request instanceof Request) {
            return;
        }

        foreach (preg_grep(self::CALLER_MEMO, $request->attributes->keys()) ?: [] as $key) {
            $request->attributes->remove($key);
        }
    }

    /**
     * Flush the session, when it is resolved and is a session, through the
     * contract Laravel aliases `session.store` to and `laravel-mfa`'s proof
     * store is given.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function flushSession(): void
    {
        if (!$this->container->resolved(Session::class)) {
            return;
        }

        $session = $this->resolve(Session::class);

        // An application may bind something other than a session to
        // `session.store`, which holds no proofs to flush.
        if (!$session instanceof Session) {
            return;
        }

        $session->flush();
    }

    /**
     * Resolve the abstract as whatever the container holds for it, which an
     * application may have bound to anything, not as the abstract promises.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolve(string $abstract): mixed
    {
        return $this->container->make($abstract);
    }

    /**
     * Whether the scoped abstract holds the suite's request state: a member's,
     * as listed, one of `laravel-authorization`'s scoped defaults, under the
     * keys it holds them under, or one of this package's scoped adapters, under
     * the keys the binding rule scopes them under.
     *
     * @param  string  $abstract
     * @return bool
     */
    private static function isSuiteState(string $abstract): bool
    {
        return in_array($abstract, self::SCOPED_STATE, true)
            || str_starts_with($abstract, self::AUTHORIZATION_DEFAULT)
            || str_starts_with($abstract, BindingRule::SCOPED_PREFIX);
    }

    /**
     * Return the abstracts the container keeps as scoped, from the property
     * Laravel's own `forgetScopedInstances()` reads, which the container
     * exposes no other way: each a string, or the closure itself for a binding
     * scoped by its closure's return type.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return array<array-key, (\Closure(mixed...): mixed)|string>
     */
    private static function scopedAbstracts(IlluminateContainer $container): array
    {
        return \Closure::bind(static fn (IlluminateContainer $container): array => $container->scopedInstances, null, IlluminateContainer::class)($container);
    }
}
