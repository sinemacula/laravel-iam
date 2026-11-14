<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Context\Enums\AuthenticationKey;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextKeys;
use SineMacula\Laravel\Sso\Sessions\Enums\ContextKey;

/**
 * Unit tests for the authentication context's declared keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContextKeys::class)]
final class AuthenticationContextKeysTest extends TestCase
{
    /**
     * Every authentication key is declared with the type authentication gives
     * it.
     *
     * @return void
     */
    public function testEveryAuthenticationKeyIsDeclaredWithItsType(): void
    {
        $keys = AuthenticationContextKeys::keys();

        self::assertSame(ContextKeyType::STRING, $keys[AuthenticationKey::IDENTITY_ID->value] ?? null);
        self::assertSame(ContextKeyType::LIST, $keys[AuthenticationKey::AMR->value] ?? null);
        self::assertSame(ContextKeyType::NUMBER, $keys[AuthenticationKey::SECONDS_SINCE_STEP_UP->value] ?? null);
        self::assertSame(ContextKeyType::BOOL, $keys[AuthenticationKey::MFA->value] ?? null);
        self::assertSame(ContextKeyType::IP, $keys[AuthenticationKey::IP->value] ?? null);
        self::assertSame(ContextKeyType::TIME, $keys[AuthenticationKey::AUTH_TIME->value] ?? null);

        foreach (AuthenticationKey::cases() as $key) {
            self::assertSame($key->type()->value, $keys[$key->value]->value ?? null, $key->value);
        }
    }

    /**
     * Every SSO key is declared with the type SSO gives it.
     *
     * @return void
     */
    public function testEverySsoKeyIsDeclaredWithItsType(): void
    {
        $keys = AuthenticationContextKeys::keys();

        self::assertSame(ContextKeyType::STRING, $keys[ContextKey::CONNECTION->value] ?? null);
        self::assertSame(ContextKeyType::LIST, $keys[ContextKey::PROVIDER_AMR->value] ?? null);
        self::assertSame(ContextKeyType::TIME, $keys[ContextKey::SESSION_NOT_AFTER->value] ?? null);

        foreach (ContextKey::cases() as $key) {
            self::assertArrayHasKey($key->value, $keys);
        }
    }

    /**
     * The MFA keys are declared alongside authentication's and SSO's.
     *
     * @return void
     */
    public function testTheListedKeysAreKept(): void
    {
        $keys = AuthenticationContextKeys::keys();

        foreach (AuthenticationContextKeys::KEYS as $path => $type) {
            self::assertSame($type, $keys[$path] ?? null, $path);
        }

        self::assertCount(count(AuthenticationContextKeys::KEYS) + count(AuthenticationKey::cases()) + count(ContextKey::cases()), $keys);
    }
}
