<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext as Context;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContexts;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization`'s authentication context,
 * answered by `laravel-authentication`'s (IAM-6.2): the namespaces are always
 * `authentication`, `mfa` and `sso`; the values are the request's context as
 * `laravel-authentication` holds it, with its own key names and the `mfa`
 * namespace MFA's contributor fills, so a step-up shows; a guest has none; and
 * a namespace an application's own contributor adds is not supplied. The values
 * depend on the request alone, so the context is scope invariant.
 *
 * Each scenario that signs in runs at the connection's own level on every
 * engine, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContextAdapter::class)]
final class AuthenticationContextAdapterTest extends TestCase
{
    use InteractsWithIam, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /**
     * The context supplies `authentication`, `mfa` and `sso`, whoever is signed
     * in, and is scope invariant.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheNamespacesAreFixed(): void
    {
        $context = $this->context();

        self::assertSame(['authentication', 'mfa', 'sso'], $context->namespaces());
        self::assertInstanceOf(ScopeInvariant::class, $context);
    }

    /**
     * A guest has no values, so every key is missing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuestHasNoValues(): void
    {
        self::assertSame([], $this->context()->values());
    }

    /**
     * The values are the request's context as `laravel-authentication` holds
     * it, keyed as it keys them, with MFA's namespace beside its own, so the
     * session's step-up shows.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheValuesAreTheRequestsContext(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $values = $this->context()->values();

        self::assertSame(Auth::context()?->toArray(), $values);
        self::assertSame(self::GUARD, $values['authentication']['application']);
        self::assertFalse($values['mfa']['accepted']);

        $this->actingOnVerifiedSession($session);

        $values = $this->context()->values();

        self::assertTrue($values['mfa']['accepted']);
        self::assertTrue($values['authentication']['mfa']);
    }

    /**
     * A namespace another contributor adds is not supplied.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANamespaceAnotherContributorAddsIsNotSupplied(): void
    {
        $context = new Context(
            subjectType: SubjectType::PERSON,
            identityType: 'person',
            identityId: '1',
            principalType: 'person',
            principalId: '1',
            tenantType: null,
            tenantId: null,
            application: self::GUARD,
            sessionId: null,
            amr: [],
            authTime: null,
            mfa: false,
            recoveryCode: false,
            multifactor: false,
            secondsSinceStepUp: null,
            credential: null,
            scopes: null,
            ip: null,
            contributed: ['billing' => ['plan' => 'gold'], 'sso' => ['connection' => 'okta']],
        );

        $contexts = \Mockery::mock(AuthenticationContexts::class);

        $contexts->allows('current')->andReturn($context);

        $this->app?->instance(AuthenticationContexts::class, $contexts);

        self::assertSame(['authentication', 'sso'], array_keys($this->context()->values()));
        self::assertSame(['connection' => 'okta'], $this->context()->values()['sso']);
    }

    /**
     * The bound authentication context.
     *
     * @return \SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function context(): AuthenticationContextAdapter
    {
        $context = $this->resolved(AuthenticationContext::class);

        self::assertInstanceOf(AuthenticationContextAdapter::class, $context);

        return $context;
    }

    /**
     * Resolve the abstract from the application under test, as anything that
     * asks for it does.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
