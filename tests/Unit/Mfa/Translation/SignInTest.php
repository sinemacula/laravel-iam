<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use Illuminate\Auth\GenericUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Unit tests for naming one of `laravel-authentication`'s sessions as MFA names
 * a sign-in, and binding the proofs read from it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignIn::class)]
final class SignInTest extends TestCase
{
    /**
     * Rows of `[session key, reference]` for the keys a session may have.
     *
     * @return iterable<string, array{0: int|string, 1: string}>
     */
    public static function provideSessionKeys(): iterable
    {
        yield 'an integer' => [42, '42'];

        yield 'a string' => ['01JC0000000000000000000000', '01JC0000000000000000000000'];
    }

    /**
     * A session is named by its key as a string.
     *
     * @param  int|string  $key
     * @param  string  $reference
     * @return void
     */
    #[DataProvider('provideSessionKeys')]
    public function testASessionIsNamedByItsKey(int|string $key, string $reference): void
    {
        self::assertSame($reference, SignIn::reference($this->session($key), 'api'));
    }

    /**
     * Rows of `[session key]` MFA cannot name a sign-in by.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnsupportedSessionKeys(): iterable
    {
        yield 'none' => [null];

        yield 'empty' => [''];

        yield 'a number with a fraction' => [4.2];
    }

    /**
     * A session whose key MFA cannot name is refused, as a session that cannot
     * be resolved on the application.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('provideUnsupportedSessionKeys')]
    public function testASessionKeyMfaCannotNameIsRefused(mixed $key): void
    {
        try {
            SignIn::reference($this->session($key), 'api');

            self::fail('A session was named by a key MFA cannot hold.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::SESSION, $exception->kind);
            self::assertSame('api', $exception->application);
        }
    }

    /**
     * A proof read from the sign-in is bound to its identity, application and
     * session, for the purpose given.
     *
     * @return void
     */
    public function testAProofIsBoundToTheSignIn(): void
    {
        $signIn = new SignIn(ProofOwner::of(new GenericUser(['id' => 7])), 'api', '42', 3);

        self::assertEquals(new ProofBinding(GenericUser::class, '7', 'api', '42', Purpose::STEP_UP), $signIn->binding(Purpose::STEP_UP));
        self::assertSame(3, $signIn->generation);
    }

    /**
     * Build a session with the given key.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     */
    private function session(mixed $key): Session
    {
        $session = self::createStub(Session::class);

        $session->method('getSessionIdentifier')->willReturn($key);

        return $session;
    }
}
