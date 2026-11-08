<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\Iam\Audit\Correlation;

/**
 * Unit tests for the correlation ids the mappers tie records together with
 * (IAM-9.5): each source's namespace and format, `null` for a missing or empty
 * part, an id of at most 191 bytes, an id audit-log would refuse being no id at
 * all, and the first of several candidates.
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
     * An id of exactly 191 bytes is one; one byte more is none.
     *
     * @return void
     */
    public function testAnIdIsAtMost191Bytes(): void
    {
        $longest = Correlation::session(str_repeat('a', Correlation::MAX_BYTES - strlen('session:')));

        self::assertSame(Correlation::MAX_BYTES, strlen((string) $longest));
        self::assertNull(Correlation::session(str_repeat('a', Correlation::MAX_BYTES - strlen('session:') + 1)));
        self::assertSame(191, Correlation::MAX_BYTES);
    }

    /**
     * The cap counts bytes, not characters: an id of fewer than 191 characters
     * that is longer than 191 bytes is none.
     *
     * @return void
     */
    public function testTheCapCountsBytes(): void
    {
        $value = str_repeat('é', 92);

        self::assertLessThan(Correlation::MAX_BYTES, mb_strlen('session:' . $value));
        self::assertNull(Correlation::session($value));
        self::assertSame('session:' . str_repeat('é', 91), Correlation::session(str_repeat('é', 91)));
    }

    /**
     * Rows of `[value]` audit-log would refuse in an id.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUncleanValues(): iterable
    {
        yield 'a leading space' => [' session-1'];

        yield 'a line feed' => ["session\n1"];

        yield 'a tab' => ["session\t1"];

        yield 'a null byte' => ["session\x001"];

        yield 'a delete' => ["session\x7F1"];

        yield 'a right-to-left override' => ["session\u{202E}1"];

        yield 'a first isolate' => ["session\u{2068}1"];

        yield 'malformed UTF-8' => ["session\xC31"];
    }

    /**
     * An id audit-log would refuse is no id, so the record is never lost to the
     * refusal.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideUncleanValues')]
    public function testAnIdAuditLogWouldRefuseIsNone(string $value): void
    {
        self::assertNull(Correlation::session($value));
    }

    /**
     * Every id given is one audit-log takes.
     *
     * @return void
     */
    public function testEveryIdIsOneAuditLogTakes(): void
    {
        $ids = [
            Correlation::ssoSignIn('01JC0000000000000000000000', 'AAAA-bbbb_cccc'),
            Correlation::session(str_repeat('a', Correlation::MAX_BYTES - strlen('session:'))),
            Correlation::mfaChallenge('ünïcode'),
        ];

        foreach ($ids as $id) {
            self::assertIsString($id);
            self::assertSame($id, (new PendingRecord)->correlatedWith($id)->snapshot()->correlationId);
        }
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
