<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use Tests\Fixtures\Models\Machine;

/**
 * Unit tests for answering the scopes the subject carries: a subject's own
 * scopes, a list or an empty one, are answered as they are, for a person and a
 * machine alike, and a subject carrying none is answered no cap, but for a
 * machine, which is answered a cap allowing nothing, however it is one of
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

    /**
     * Rows of `[the scopes the subject carries]`.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideScopes(): iterable
    {
        yield 'two scopes' => [['reports:read', 'reports:export']];

        yield 'none granted' => [[]];
    }

    /**
     * The scopes a person's subject carries are answered as they are, an empty
     * list, which allows nothing, included.
     *
     * @param  list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideScopes')]
    public function testAPersonsOwnScopesAreAnswered(array $scopes): void
    {
        $principal = $this->principalActingFor($this->identity(Identity::class));

        self::assertSame($scopes, (new SessionPolicySourceAdapter)->scopesFor(self::subject($principal, null, $scopes)));
    }

    /**
     * A person whose subject carries no scopes, on a session no credential
     * limits or named by the caller, is answered no cap.
     *
     * @return void
     */
    public function testAPersonCarryingNoScopesIsAnsweredNoCap(): void
    {
        $principal = $this->principalActingFor($this->identity(Identity::class));

        self::assertNull((new SessionPolicySourceAdapter)->scopesFor(self::subject($principal, null, null)));
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
     * A machine carrying no scopes is answered a cap allowing nothing, never no
     * cap, whether or not it carries `laravel-authorization`'s marker, however
     * it is a machine: `laravel-authorization` allows nothing to a machine
     * answered `null` only when it carries the marker.
     *
     * @param  \Closure(self): object  $subject
     * @param  \Closure(self): ?object  $identity
     * @return void
     */
    #[DataProvider('provideMachines')]
    public function testAMachineCarryingNoScopesIsAllowedNothing(\Closure $subject, \Closure $identity): void
    {
        self::assertSame([], (new SessionPolicySourceAdapter)->scopesFor(self::subject($subject($this), $identity($this), null)));
    }

    /**
     * A machine carrying its credential's scopes is answered them, however it
     * is a machine, never a cap allowing nothing in their place.
     *
     * @param  \Closure(self): object  $subject
     * @param  \Closure(self): ?object  $identity
     * @return void
     */
    #[DataProvider('provideMachines')]
    public function testAMachinesOwnScopesAreAnswered(\Closure $subject, \Closure $identity): void
    {
        self::assertSame(['reports:read'], (new SessionPolicySourceAdapter)->scopesFor(self::subject($subject($this), $identity($this), ['reports:read'])));
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
     * A subject on the guard, with no session, carrying the scopes given.
     *
     * @param  object  $subject
     * @param  ?object  $identity
     * @param  ?list<string>  $scopes
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function subject(object $subject, ?object $identity, ?array $scopes): Subject
    {
        return new Subject($subject, $identity, null, self::GUARD, self::GUARD, scopes: $scopes);
    }
}
