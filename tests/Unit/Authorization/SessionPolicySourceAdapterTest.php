<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Models\Machine;

/**
 * Unit tests for the order the source answers in: the scopes a subject says its
 * credential carries are answered as they are, no cap and a list alike, with
 * nothing read for them; a subject naming a session the source cannot establish
 * (no guard, no identity of its own, no session service, or a lookup that
 * throws) is allowed nothing; a subject naming a guard is answered from that
 * guard's caller only while the caller is the subject's own model, by object or
 * by model, and only once the guard has resolved its request, and is allowed
 * nothing when the guard cannot be read; and a subject naming no credential is
 * answered no cap for a person and a cap allowing nothing for a machine,
 * however it is one of `laravel-authentication`'s machines.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPolicySourceAdapter::class)]
final class SessionPolicySourceAdapterTest extends TestCase
{
    /** @var string The guard the subject names. */
    private const string GUARD = 'api';

    /** @var list<string> The scopes the guard's credential carries. */
    private const array SCOPES = ['reports:read'];

    /**
     * Rows of `[what the subject says its credential carries, the answer]`.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authorization\Support\CredentialScopes, 1: ?list<string>}>
     */
    public static function provideSaidScopes(): iterable
    {
        yield 'no cap' => [static fn (): CredentialScopes => CredentialScopes::uncapped(), null];

        yield 'two scopes' => [static fn (): CredentialScopes => CredentialScopes::of(['reports:read', 'reports:export']), ['reports:read', 'reports:export']];

        yield 'none granted' => [static fn (): CredentialScopes => CredentialScopes::of([]), []];
    }

    /**
     * The scopes a subject says its credential carries are answered as they
     * are, for a person and a machine alike, and nothing is read for them, the
     * session and guard it names included.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authorization\Support\CredentialScopes  $said
     * @param  ?list<string>  $answer
     * @return void
     */
    #[DataProvider('provideSaidScopes')]
    public function testTheScopesASubjectSaysAreAnswered(\Closure $said, ?array $answer): void
    {
        $source = new SessionPolicySourceAdapter($this->unread());

        self::assertSame($answer, $source->scopesFor(new Subject($this->person(), null, null, self::GUARD, self::GUARD, 'session-1', $said())));
        self::assertSame($answer, $source->scopesFor(new Subject(new Machine, null, null, self::GUARD, self::GUARD, scopes: $said())));
    }

    /**
     * A person naming no credential, neither a session nor a guard, carries no
     * cap, and nothing is read for it.
     *
     * @return void
     */
    public function testAPersonNamingNoCredentialIsAnsweredNoCap(): void
    {
        self::assertNull((new SessionPolicySourceAdapter($this->unread()))->scopesFor(new Subject($this->person())));
        self::assertFalse(SessionPolicySourceAdapter::withoutCredential($this->person())->isCapped());
    }

    /**
     * Rows of `[the subject, its identity]`: each a machine of
     * `laravel-authentication`'s by one sign alone, carrying no marker of
     * `laravel-authorization`'s (`AuthorizableMachine`).
     *
     * @return iterable<string, array{0: \Closure(self): object, 1: \Closure(self): ?object}>
     */
    public static function provideMachines(): iterable
    {
        yield 'a machine identity as the subject' => [static fn (): object => new Machine, static fn (): ?object => null];

        yield 'a machine identity as the identity' => [
            static fn (self $test): object => $test->principalActingFor($test->identity(Identity::class)),
            static fn (): object => new Machine,
        ];

        yield 'a principal acting for a machine identity' => [
            static fn (self $test): object => $test->principalActingFor($test->identity(MachineIdentity::class)),
            static fn (): ?object => null,
        ];
    }

    /**
     * A machine naming no credential is allowed nothing, never no cap, however
     * it is a machine, and that is what is said of it without a credential.
     *
     * @param  \Closure(self): object  $subject
     * @param  \Closure(self): ?object  $identity
     * @return void
     */
    #[DataProvider('provideMachines')]
    public function testAMachineNamingNoCredentialIsAllowedNothing(\Closure $subject, \Closure $identity): void
    {
        $model = $subject($this);
        $named = $identity($this);

        self::assertSame([], (new SessionPolicySourceAdapter($this->unread()))->scopesFor(new Subject($model, $named)));
        self::assertSame([], SessionPolicySourceAdapter::withoutCredential($model, $named)->scopes());
    }

    /**
     * Rows of `[the subject naming a session, the authentication factory]`:
     * each a session the source cannot establish.
     *
     * @return iterable<string, array{0: \Closure(self): \SineMacula\Laravel\Authorization\Subject, 1: \Closure(self): \Illuminate\Contracts\Auth\Factory}>
     */
    public static function provideUnestablishedSessions(): iterable
    {
        yield 'no guard named' => [
            static fn (self $test): Subject => new Subject($test->person(), session: 'session-1'),
            static fn (self $test): AuthFactory => $test->sessionsThrowing(),
        ];

        yield 'a subject that is no identity' => [
            static fn (): Subject => new Subject(new \stdClass, guard: self::GUARD, session: 'session-1'),
            static fn (self $test): AuthFactory => $test->sessionsThrowing(),
        ];

        yield 'a principal acting for another identity than the one named' => [
            static fn (self $test): Subject => new Subject($test->person(), $test->identity(Identity::class), guard: self::GUARD, session: 'session-1'),
            static fn (self $test): AuthFactory => $test->sessionsThrowing(),
        ];

        yield 'an authentication factory with no session service' => [
            static fn (self $test): Subject => new Subject($test->person(), guard: self::GUARD, session: 'session-1'),
            static fn (): AuthFactory => self::createStub(AuthFactory::class),
        ];

        yield 'a session service that cannot be asked' => [
            static fn (self $test): Subject => new Subject($test->person(), guard: self::GUARD, session: 'session-1'),
            static fn (self $test): AuthFactory => $test->sessionsThrowing(),
        ];
    }

    /**
     * A session the source cannot establish allows nothing, and the source
     * never throws for it.
     *
     * @param  \Closure(self): \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \Closure(self): \Illuminate\Contracts\Auth\Factory  $auth
     * @return void
     */
    #[DataProvider('provideUnestablishedSessions')]
    public function testASessionThatCannotBeEstablishedAllowsNothing(\Closure $subject, \Closure $auth): void
    {
        self::assertSame([], (new SessionPolicySourceAdapter($auth($this)))->scopesFor($subject($this)));
    }

    /**
     * The session a principal names is looked up on the guard it names, for the
     * identity it acts for, the one it names among them, whose session service
     * is asked.
     *
     * @return void
     */
    public function testASessionIsLookedUpOnTheGuardTheSubjectNames(): void
    {
        $identity = $this->identity(Identity::class);
        $auth     = $this->createMock(AuthManager::class);

        $auth->expects(self::once())->method('sessions')->with(self::GUARD)->willThrowException(new \LogicException('No session service.'));

        self::assertSame([], (new SessionPolicySourceAdapter($auth))->scopesFor(new Subject($this->principalActingFor($identity), $identity, guard: self::GUARD, session: 'session-1')));
    }

    /**
     * Rows of `[the guard's principal, its identity, the subject's model]`: the
     * guard's caller is the subject's own model.
     *
     * @return iterable<string, array{0: \Closure(self): object, 1: \Closure(): ?object, 2: \Closure(object): object}>
     */
    public static function provideCallers(): iterable
    {
        yield 'the principal, as the very object' => [
            static fn (self $test): object => $test->person(),
            static fn (): ?object => null,
            static fn (object $principal): object => $principal,
        ];

        yield 'the principal, as the same model' => [
            static fn (): object => (new Member)->forceFill(['id' => 3]),
            static fn (): ?object => null,
            static fn (): object => (new Member)->forceFill(['id' => 3]),
        ];

        yield 'the identity the principal acts for, as the same model' => [
            static fn (self $test): object => $test->person(),
            static fn (): object => (new Machine)->forceFill(['id' => 7]),
            static fn (): object => (new Machine)->forceFill(['id' => 7]),
        ];
    }

    /**
     * A subject naming a guard whose caller is its own model is answered from
     * the caller's credential.
     *
     * @param  \Closure(self): object  $principal
     * @param  \Closure(): ?object  $identity
     * @param  \Closure(object): object  $model
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAGuardsOwnCallerIsAnsweredFromItsCredential(\Closure $principal, \Closure $identity, \Closure $model): void
    {
        $held   = $principal($this);
        $source = new SessionPolicySourceAdapter($this->guardHolding($held, $identity()));

        self::assertSame(self::SCOPES, $source->scopesFor(new Subject($model($held), guard: self::GUARD)));
    }

    /**
     * A subject naming a guard whose caller is someone else, or that holds no
     * caller, names no credential of its own: no cap for a person, nothing for
     * a machine.
     *
     * @return void
     */
    public function testAGuardWhoseCallerIsSomeoneElseNamesNoCredential(): void
    {
        $caller = (new Member)->forceFill(['id' => 3]);

        self::assertNull((new SessionPolicySourceAdapter($this->guardHolding($caller, null)))->scopesFor(new Subject((new Member)->forceFill(['id' => 4]), guard: self::GUARD)));
        self::assertSame([], (new SessionPolicySourceAdapter($this->guardHolding($caller, (new Machine)->forceFill(['id' => 1]))))->scopesFor(new Subject((new Machine)->forceFill(['id' => 2]), guard: self::GUARD)));
        self::assertNull((new SessionPolicySourceAdapter($this->guardHolding(null, null)))->scopesFor(new Subject($this->person(), guard: self::GUARD)));
    }

    /**
     * A guard that has not resolved its request names no credential yet, and
     * its resolution is never started: neither its principal, identity nor
     * scopes are read.
     *
     * @return void
     */
    public function testAGuardThatHasNotResolvedItsRequestIsNeverEntered(): void
    {
        $guard = $this->createMock(ContextualGuard::class);
        $guard->method('hasUser')->willReturn(false);
        $guard->expects(self::never())->method('principal');
        $guard->expects(self::never())->method('identity');
        $guard->expects(self::never())->method('scopes');

        $auth = $this->createMock(AuthFactory::class);
        $auth->expects(self::once())->method('guard')->with(self::GUARD)->willReturn($guard);

        self::assertNull((new SessionPolicySourceAdapter($auth))->scopesFor(new Subject($this->person(), guard: self::GUARD)));
    }

    /**
     * A guard that is not `laravel-authentication`'s names no credential the
     * source can read: no cap for a person.
     *
     * @return void
     */
    public function testAGuardThatIsNotContextualNamesNoCredential(): void
    {
        $auth = self::createStub(AuthFactory::class);
        $auth->method('guard')->willReturn(self::createStub(Guard::class));

        self::assertNull((new SessionPolicySourceAdapter($auth))->scopesFor(new Subject($this->person(), guard: self::GUARD)));
    }

    /**
     * A guard that cannot be read, one that is not configured or whose caller
     * cannot be resolved, allows nothing, and the source does not throw.
     *
     * @return void
     */
    public function testAGuardThatCannotBeReadAllowsNothing(): void
    {
        $auth = self::createStub(AuthFactory::class);
        $auth->method('guard')->willThrowException(new \InvalidArgumentException('Auth guard [api] is not defined.'));

        self::assertSame([], (new SessionPolicySourceAdapter($auth))->scopesFor(new Subject($this->person(), guard: self::GUARD)));
    }

    /**
     * A principal acting for the identity given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function principalActingFor(Identity $identity): Principal
    {
        $principal = self::createStub(Principal::class);
        $principal->method('getIdentity')->willReturn($identity);

        return $principal;
    }

    /**
     * An identity of the kind given.
     *
     * @param  class-string<\SineMacula\Laravel\Authentication\Contracts\Identity>  $kind
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    public function identity(string $kind): Identity
    {
        return self::createStub($kind);
    }

    /**
     * A person: a principal acting for an identity that is no machine.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function person(): Principal
    {
        return $this->principalActingFor($this->identity(Identity::class));
    }

    /**
     * An authentication factory whose session service cannot be asked.
     *
     * @return \Illuminate\Contracts\Auth\Factory
     */
    public function sessionsThrowing(): AuthFactory
    {
        $auth = self::createStub(AuthManager::class);
        $auth->method('sessions')->willThrowException(new \LogicException('No session service.'));

        return $auth;
    }

    /**
     * An authentication factory that is asked for neither a guard nor a session
     * service.
     *
     * @return \Illuminate\Contracts\Auth\Factory
     */
    private function unread(): AuthFactory
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->expects(self::never())->method('guard');
        $auth->expects(self::never())->method('sessions');

        return $auth;
    }

    /**
     * An authentication factory whose guard has resolved its request to the
     * principal and identity given, its credential carrying the scopes.
     *
     * @param  ?object  $principal
     * @param  ?object  $identity
     * @return \Illuminate\Contracts\Auth\Factory
     */
    private function guardHolding(?object $principal, ?object $identity): AuthFactory
    {
        $guard = self::createStub(ContextualGuard::class);
        $guard->method('hasUser')->willReturn(true);
        $guard->method('principal')->willReturn($principal);
        $guard->method('identity')->willReturn($identity);
        $guard->method('scopes')->willReturn(self::SCOPES);

        $auth = $this->createMock(AuthFactory::class);
        $auth->expects(self::once())->method('guard')->with(self::GUARD)->willReturn($guard);

        return $auth;
    }
}
