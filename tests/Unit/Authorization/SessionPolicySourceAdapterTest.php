<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Models\Machine;

/**
 * Unit tests for reading a credential's scopes only while the subject's guard
 * holds that very subject and, where the subject names one, that very session:
 * a guard holding a scoped credential for a session answers its scopes for a
 * subject naming that session, by its key compared as text, and no cap for a
 * subject naming another, for a guard whose session has no key that could be
 * named, or none at all, or for a guard that has not resolved its request yet,
 * whose resolution is never started. A machine the guard does not hold is
 * answered a cap allowing nothing, however it is one of
 * `laravel-authentication`'s machines, and never no cap.
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
     * Rows of `[the key of the guard's session, the session the subject
     * names, whether the scopes are answered]`.
     *
     * @return iterable<string, array{0: mixed, 1: ?string, 2: bool}>
     */
    public static function provideSessions(): iterable
    {
        yield 'the session the guard holds, by a text key' => ['session-1', 'session-1', true];

        yield 'the session the guard holds, by a whole-number key' => [42, '42', true];

        yield 'another session' => ['session-1', 'session-2', false];

        yield 'a session whose key is no text or number' => [4.2, '4.2', false];

        yield 'a session while the guard holds none' => [null, 'session-1', false];

        yield 'no session named' => ['session-1', null, true];
    }

    /**
     * The scopes are answered only for the session the guard holds, where the
     * subject names one.
     *
     * @param  mixed  $held
     * @param  ?string  $named
     * @param  bool  $answered
     * @return void
     */
    #[DataProvider('provideSessions')]
    public function testTheScopesAreAnsweredOnlyForTheSessionTheGuardHolds(mixed $held, ?string $named, bool $answered): void
    {
        $principal = self::createStub(Principal::class);
        $source    = new SessionPolicySourceAdapter($this->auth($principal, $held));

        self::assertSame($answered ? self::SCOPES : null, $source->scopesFor(new Subject($principal, $principal, null, self::GUARD, self::GUARD, $named)));
    }

    /**
     * A principal that is no model is matched only as the very object the guard
     * holds.
     *
     * @return void
     */
    public function testAPrincipalThatIsNoModelIsMatchedAsTheVeryObject(): void
    {
        $principal = self::createStub(Principal::class);
        $source    = new SessionPolicySourceAdapter($this->auth($principal, null));

        self::assertNull($source->scopesFor(new Subject(self::createStub(Principal::class), null, null, self::GUARD, self::GUARD)));
    }

    /**
     * A principal that is no model is never matched to a subject that is one,
     * nor a model principal to a subject that is none.
     *
     * @return void
     */
    public function testAModelAndAPrincipalThatIsNoneAreNeverMatched(): void
    {
        $member = new Member(['name' => 'Ada Lovelace']);
        $other  = self::createStub(Principal::class);

        self::assertNull((new SessionPolicySourceAdapter($this->auth($other, null)))->scopesFor(new Subject($member, null, null, self::GUARD, self::GUARD)));
        self::assertNull((new SessionPolicySourceAdapter($this->auth($member, null)))->scopesFor(new Subject($other, null, null, self::GUARD, self::GUARD)));
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
     * A machine the guard does not hold is answered a cap allowing nothing,
     * never no cap, whether or not it carries `laravel-authorization`'s marker,
     * however it is a machine: `laravel-authorization` allows nothing to a
     * machine answered `null` only when it carries the marker.
     *
     * @param  \Closure(self): object  $subject
     * @param  \Closure(self): ?object  $identity
     * @return void
     */
    #[DataProvider('provideMachines')]
    public function testAMachineTheGuardDoesNotHoldIsAllowedNothing(\Closure $subject, \Closure $identity): void
    {
        $source = new SessionPolicySourceAdapter($this->auth(self::createStub(Principal::class), null));

        self::assertSame([], $source->scopesFor(new Subject($subject($this), $identity($this), null, self::GUARD, self::GUARD)));
    }

    /**
     * A machine naming no guard is answered a cap allowing nothing too, and no
     * guard is read for it.
     *
     * @return void
     */
    public function testAMachineNamingNoGuardIsAllowedNothing(): void
    {
        $auth = $this->createMock(AuthFactory::class);
        $auth->expects(self::never())->method('guard');

        self::assertSame([], (new SessionPolicySourceAdapter($auth))->scopesFor(new Subject(new Machine, null, null, null, null)));
    }

    /**
     * A principal acting for a person is no machine, so a principal the guard
     * does not hold is answered no cap.
     *
     * @return void
     */
    public function testAPrincipalActingForAPersonIsAnsweredNoCap(): void
    {
        $source = new SessionPolicySourceAdapter($this->auth(self::createStub(Principal::class), null));

        self::assertNull($source->scopesFor(new Subject($this->principalActingFor($this->identity(Identity::class)), null, null, self::GUARD, self::GUARD)));
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
     * A subject naming no guard carries no cap, and no guard is read for it,
     * the default one included.
     *
     * @return void
     */
    public function testASubjectNamingNoGuardReadsNoGuard(): void
    {
        $auth = $this->createMock(AuthFactory::class);
        $auth->expects(self::never())->method('guard');

        self::assertNull((new SessionPolicySourceAdapter($auth))->scopesFor(new Subject(self::createStub(Principal::class), null, null, null, null)));
    }

    /**
     * A guard that holds no principal answers no cap.
     *
     * @return void
     */
    public function testAGuardHoldingNoPrincipalAnswersNoCap(): void
    {
        $source = new SessionPolicySourceAdapter($this->auth(null, null));

        self::assertNull($source->scopesFor(new Subject(self::createStub(Principal::class), null, null, self::GUARD, self::GUARD)));
    }

    /**
     * A guard that has not resolved its request yet answers no cap, and its
     * resolution is never started: neither its identity, principal, session nor
     * scopes are read.
     *
     * @return void
     */
    public function testAGuardThatHasNotResolvedItsRequestIsNeverEntered(): void
    {
        $guard = $this->createMock(ContextualGuard::class);
        $guard->method('hasUser')->willReturn(false);
        $guard->expects(self::never())->method('user');
        $guard->expects(self::never())->method('principal');
        $guard->expects(self::never())->method('session');
        $guard->expects(self::never())->method('scopes');

        $auth = $this->createMock(AuthFactory::class);
        $auth->expects(self::once())->method('guard')->with(self::GUARD)->willReturn($guard);

        self::assertNull((new SessionPolicySourceAdapter($auth))->scopesFor(new Subject(self::createStub(Principal::class), null, null, self::GUARD, self::GUARD)));
    }

    /**
     * An authentication factory whose guard holds the principal, a session of
     * the key given (none for `null`) and a credential carrying the scopes.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  mixed  $session
     * @return \Illuminate\Contracts\Auth\Factory
     */
    private function auth(?Principal $principal, mixed $session): AuthFactory
    {
        $held = null;

        if ($session !== null) {
            $held = self::createStub(Session::class);
            $held->method('getSessionIdentifier')->willReturn($session);
        }

        $guard = self::createStub(ContextualGuard::class);
        $guard->method('hasUser')->willReturn(true);
        $guard->method('principal')->willReturn($principal);
        $guard->method('session')->willReturn($held);
        $guard->method('scopes')->willReturn(self::SCOPES);

        $auth = $this->createMock(AuthFactory::class);
        $auth->expects(self::once())->method('guard')->with(self::GUARD)->willReturn($guard);

        return $auth;
    }
}
