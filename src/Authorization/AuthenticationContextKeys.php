<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Context\Enums\AuthenticationKey;
use SineMacula\Laravel\Authentication\Context\Enums\ContextKeyType as AuthenticationValueType;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Sso\Sessions\Enums\ContextKey as SsoContextKey;
use SineMacula\Laravel\Sso\Sessions\Enums\ContextValueType as SsoValueType;

/**
 * Declares the authentication context's keys and their types on
 * `laravel-authorization`'s key catalogue, leaving keys already declared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationContextKeys
{
    /** @var array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType> The MFA keys, by dot path, with their types. */
    public const array KEYS = [
        'mfa.accepted'                      => ContextKeyType::BOOL,
        'mfa.multifactor'                   => ContextKeyType::BOOL,
        'mfa.factor_types'                  => ContextKeyType::LIST,
        'mfa.level'                         => ContextKeyType::STRING,
        'mfa.phishing_resistant'            => ContextKeyType::BOOL,
        'mfa.user_verification'             => ContextKeyType::BOOL,
        'mfa.last_verification_age_seconds' => ContextKeyType::NUMBER,
        'mfa.has_confirmed_factor'          => ContextKeyType::BOOL,
    ];

    /**
     * Every key declared, by its dot path, with its type; authentication and
     * SSO name their own.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType>
     */
    public static function keys(): array
    {
        $keys = self::KEYS;

        foreach (AuthenticationKey::cases() as $key) {
            $keys[$key->value] = self::authenticationType($key->type());
        }

        foreach (SsoContextKey::cases() as $key) {
            $keys[$key->value] = self::ssoType($key->type());
        }

        return $keys;
    }

    /**
     * Declare the keys once the catalogue is built, while the context is ours.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     */
    public static function register(Container $container): void
    {
        $container->afterResolving(ContextKeyCatalogue::class, static function (ContextKeyCatalogue $catalogue, Container $container): void {

            if (!self::isAdapterBound($container)) {
                return;
            }

            self::declareOn($catalogue);
        });
    }

    /**
     * Whether the authentication context bound is this package's.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return bool
     *
     * @throws \Psr\Container\ContainerExceptionInterface
     */
    private static function isAdapterBound(Container $container): bool
    {
        return $container->bound(AuthenticationContext::class) && $container->get(AuthenticationContext::class) instanceof AuthenticationContextAdapter;
    }

    /**
     * Declare each key the catalogue does not declare yet.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue  $catalogue
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function declareOn(ContextKeyCatalogue $catalogue): void
    {
        foreach (self::keys() as $path => $type) {

            if ($catalogue->find($path) !== null) {
                continue;
            }

            $catalogue->declare($path, $type);
        }
    }

    /**
     * Authorization's type for a `laravel-authentication` key's type.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\Enums\ContextKeyType  $type
     * @return \SineMacula\Laravel\Authorization\Enums\ContextKeyType
     */
    private static function authenticationType(AuthenticationValueType $type): ContextKeyType
    {
        return match ($type) {
            AuthenticationValueType::STRING => ContextKeyType::STRING,
            AuthenticationValueType::LIST   => ContextKeyType::LIST,
            AuthenticationValueType::NUMBER => ContextKeyType::NUMBER,
            AuthenticationValueType::BOOL   => ContextKeyType::BOOL,
            AuthenticationValueType::IP     => ContextKeyType::IP,
            AuthenticationValueType::TIME   => ContextKeyType::TIME,
        };
    }

    /**
     * Authorization's type for a `laravel-sso` key's type.
     *
     * @param  \SineMacula\Laravel\Sso\Sessions\Enums\ContextValueType  $type
     * @return \SineMacula\Laravel\Authorization\Enums\ContextKeyType
     */
    private static function ssoType(SsoValueType $type): ContextKeyType
    {
        return match ($type) {
            SsoValueType::STRING => ContextKeyType::STRING,
            SsoValueType::LIST   => ContextKeyType::LIST,
            SsoValueType::TIME   => ContextKeyType::TIME,
        };
    }
}
