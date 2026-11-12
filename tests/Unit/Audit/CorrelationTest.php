<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Audit\Correlation;

/**
 * Unit tests for the correlation ids the mappers tie records together with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Correlation::class)]
final class CorrelationTest extends TestCase
{
    /**
     * Each source's id is its namespace and its parts, joined by colons.
     *
     * @return void
     */
    public function testEachSourcesFormat(): void
    {
        self::assertSame('sso:connection-1:reference-1', Correlation::ssoSignIn('connection-1', 'reference-1'));
        self::assertSame('mfa:challenge-1', Correlation::mfaChallenge('challenge-1'));
        self::assertSame('authentication:challenge-1', Correlation::authenticationChallenge('challenge-1'));
        self::assertSame('session:session-1', Correlation::session('session-1'));
        self::assertSame('authorization:operation-1', Correlation::authorizationOperation('operation-1'));
    }

    /**
     * Rows of `[id]`, each made with a part missing or empty.
     *
     * @return iterable<string, array{0: \Closure(): ?string}>
     */
    public static function provideMissingParts(): iterable
    {
        yield 'no connection' => [static fn (): ?string => Correlation::ssoSignIn(null, 'reference-1')];

        yield 'an empty connection' => [static fn (): ?string => Correlation::ssoSignIn('', 'reference-1')];

        yield 'no request' => [static fn (): ?string => Correlation::ssoSignIn('connection-1', null)];

        yield 'an empty request' => [static fn (): ?string => Correlation::ssoSignIn('connection-1', '')];

        yield 'no MFA challenge' => [static fn (): ?string => Correlation::mfaChallenge(null)];

        yield 'no challenge of authentication\'s' => [static fn (): ?string => Correlation::authenticationChallenge('')];

        yield 'no session' => [static fn (): ?string => Correlation::session(null)];

        yield 'no operation' => [static fn (): ?string => Correlation::authorizationOperation(null)];
    }

    /**
     * A missing or empty part means no id at all.
     *
     * @param  \Closure(): ?string  $id
     * @return void
     */
    #[DataProvider('provideMissingParts')]
    public function testAMissingPartIsNoId(\Closure $id): void
    {
        self::assertNull($id());
    }

    /**
     * Rows of `[value]` audit-log would refuse in an id.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield 'a leading space' => [' session-1'];

        yield 'a control character' => ["session\x001"];

        yield 'over 191 characters' => [str_repeat('a', 192 - strlen('session:'))];
    }

    /**
     * An id audit-log would refuse is no id.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testAnIdAuditLogWouldRefuseIsNone(string $value): void
    {
        self::assertNull(Correlation::session($value));
    }

    /**
     * The length is counted in characters, not bytes.
     *
     * @return void
     */
    public function testTheLengthCountsCharacters(): void
    {
        $value = str_repeat('é', 191 - strlen('session:'));

        self::assertSame('session:' . $value, Correlation::session($value));
    }

    /**
     * The first candidate that is an id is kept; none at all is `null`.
     *
     * @return void
     */
    public function testTheFirstIdIsKept(): void
    {
        self::assertSame('mfa:b', Correlation::first(null, 'mfa:b', 'session:c'));
        self::assertSame('sso:a:b', Correlation::first('sso:a:b', 'mfa:b'));
        self::assertNull(Correlation::first(null, null));
        self::assertNull(Correlation::first());
    }
}
