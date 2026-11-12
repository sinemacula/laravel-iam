<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Models\Machine;

/**
 * Unit tests for the edges of the subject resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectResolverAdapter::class)]
final class SubjectResolverAdapterTest extends TestCase
{
    /** @var string The default guard. */
    private const string GUARD = 'api';

    /**
     * A caller still choosing its principal is no subject.
     *
     * @return void
     */
    public function testACallerStillChoosingItsPrincipalIsNoSubject(): void
    {
        $guard = self::createStub(ContextualGuard::class);
        $auth  = self::createStub(AuthManager::class);

        $auth->method('guard')->willReturn($guard);
        $auth->method('caller')->willReturn(new Caller(self::GUARD, CallerCredential::PENDING, self::createStub(Identity::class), null, null, null));

        self::assertNull($this->resolver($auth)->resolve());
    }

    /**
     * Rows of the caller's credential scopes: no cap, a list, none granted.
     *
     * @return iterable<string, array{0: ?list<string>}>
     */
    public static function provideCredentialScopes(): iterable
    {
        yield 'no cap' => [null];

        yield 'two scopes' => [['reports:read', 'reports:export']];

        yield 'none granted' => [[]];
    }

    /**
     * The caller's scopes are the subject's.
     *
     * @param  ?list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideCredentialScopes')]
    public function testTheCallersScopesAreTheSubjects(?array $scopes): void
    {
        $principal = self::createStub(Principal::class);
        $auth      = self::createStub(AuthManager::class);

        $auth->method('guard')->willReturn(self::createStub(ContextualGuard::class));
        $auth->method('caller')->willReturn(new Caller(self::GUARD, CallerCredential::ACCESS, self::createStub(Identity::class), $principal, null, null, scopes: $scopes));

        self::assertEquals(self::said($scopes), $this->resolver($auth)->resolve()?->scopes);
    }

    /**
     * The guard's principal carries its credential's scopes.
     *
     * @param  ?list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideCredentialScopes')]
    public function testTheGuardsPrincipalCarriesItsCredentialsScopes(?array $scopes): void
    {
        $principal = self::createStub(Principal::class);
        $resolver  = $this->resolver($this->guardHolding($principal, self::createStub(Identity::class), $scopes));

        self::assertEquals(self::said($scopes), $resolver->forUser($principal)->scopes);
        self::assertNull($resolver->forUser(self::createStub(Principal::class))->scopes);
    }

    /**
     * A session keyed by an integer is named as text.
     *
     * @return void
     */
    public function testASessionKeyedByAnIntegerIsNamedAsText(): void
    {
        $principal = self::createStub(Principal::class);
        $session   = self::createStub(Session::class);
        $guard     = self::createStub(ContextualGuard::class);
        $auth      = self::createStub(AuthFactory::class);

        $session->method('getSessionIdentifier')->willReturn(42);
        $guard->method('hasUser')->willReturn(true);
        $guard->method('principal')->willReturn($principal);
        $guard->method('session')->willReturn($session);
        $auth->method('guard')->willReturn($guard);

        self::assertSame('42', $this->resolver($auth)->forUser($principal)->session);
    }

    /**
     * A reloaded copy of the caller's identity is the caller.
     *
     * @return void
     */
    public function testACopyOfTheCallersIdentityLoadedAgainIsTheCaller(): void
    {
        $principal = self::createStub(Principal::class);
        $identity  = (new Machine)->forceFill(['id' => 7]);
        $resolver  = $this->resolver($this->guardHolding($principal, $identity));
        $subject   = $resolver->forUser((new Machine)->forceFill(['id' => 7]));

        self::assertSame($principal, $subject->subject);
        self::assertSame($identity, $subject->identity);
        self::assertSame('session-1', $subject->session);

        $other   = (new Machine)->forceFill(['id' => 8]);
        $subject = $resolver->forUser($other);

        self::assertSame($other, $subject->subject);
        self::assertSame($other, $subject->identity);
        self::assertNull($subject->tenant);
        self::assertNull($subject->session);
    }

    /**
     * A reloaded copy of the caller's principal is the caller.
     *
     * @return void
     */
    public function testACopyOfTheCallersPrincipalLoadedAgainIsTheCaller(): void
    {
        $principal = (new Member)->forceFill(['id' => 3]);
        $resolver  = $this->resolver($this->guardHolding($principal, $principal));
        $copy      = $resolver->forUser((new Member)->forceFill(['id' => 3]));
        $other     = (new Member)->forceFill(['id' => 4]);

        self::assertSame($principal, $copy->subject);
        self::assertSame('session-1', $copy->session);
        self::assertNull($resolver->forUser($other)->session);
        self::assertSame($other, $resolver->forUser($other)->subject);
    }

    /**
     * Another kind of guard's principal acts for its identity in its tenant.
     *
     * @return void
     */
    public function testAnotherKindOfGuardsPrincipalActsForItsIdentityInItsTenant(): void
    {
        $identity  = self::createStub(Identity::class);
        $tenant    = self::createStub(Tenant::class);
        $principal = self::createStubForIntersectionOfInterfaces([Principal::class, Authenticatable::class]);
        $guard     = self::createStub(Guard::class);
        $auth      = self::createStub(AuthFactory::class);

        $principal->method('getIdentity')->willReturn($identity);
        $principal->method('getTenant')->willReturn($tenant);
        $guard->method('user')->willReturn($principal);
        $auth->method('guard')->willReturn($guard);

        foreach ([$this->resolver($auth)->resolve(), $this->resolver($auth)->forUser($principal)] as $subject) {
            self::assertNotNull($subject);
            self::assertSame($principal, $subject->subject);
            self::assertSame($identity, $subject->identity);
            self::assertSame($tenant, $subject->tenant);
            self::assertSame(self::GUARD, $subject->application);
            self::assertSame(self::GUARD, $subject->guard);
            self::assertNull($subject->session);
        }
    }

    /**
     * The scopes said of a credential: no cap for `null`.
     *
     * @param  ?list<string>  $scopes
     * @return \SineMacula\Laravel\Authorization\Support\CredentialScopes
     */
    private static function said(?array $scopes): CredentialScopes
    {
        return $scopes === null ? CredentialScopes::uncapped() : CredentialScopes::of($scopes);
    }

    /**
     * An auth factory whose default guard holds the principal and identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?list<string>  $scopes
     * @return \Illuminate\Contracts\Auth\Factory
     */
    private function guardHolding(Principal $principal, Identity $identity, ?array $scopes = null): AuthFactory
    {
        $session = self::createStub(Session::class);
        $guard   = self::createStub(ContextualGuard::class);
        $auth    = self::createStub(AuthFactory::class);

        $session->method('getSessionIdentifier')->willReturn('session-1');
        $guard->method('hasUser')->willReturn(true);
        $guard->method('principal')->willReturn($principal);
        $guard->method('identity')->willReturn($identity);
        $guard->method('session')->willReturn($session);
        $guard->method('scopes')->willReturn($scopes);
        $auth->method('guard')->willReturn($guard);

        return $auth;
    }

    /**
     * The resolver, on the default guard named in the configuration.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @return \SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter
     */
    private function resolver(AuthFactory $auth): SubjectResolverAdapter
    {
        return new SubjectResolverAdapter($auth, new Repository(['auth' => ['defaults' => ['guard' => self::GUARD]]]), new Container);
    }
}
