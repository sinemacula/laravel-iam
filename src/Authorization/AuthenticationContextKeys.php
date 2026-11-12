<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

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
    /** @var array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType> Each key declared, by its dot path, with its type. */
    public const array KEYS = [
        'authentication.subject_type'          => ContextKeyType::STRING,
        'authentication.identity_type'         => ContextKeyType::STRING,
        'authentication.identity_id'           => ContextKeyType::STRING,
        'authentication.principal_type'        => ContextKeyType::STRING,
        'authentication.principal_id'          => ContextKeyType::STRING,
        'authentication.tenant_type'           => ContextKeyType::STRING,
        'authentication.tenant_id'             => ContextKeyType::STRING,
        'authentication.application'           => ContextKeyType::STRING,
        'authentication.session_id'            => ContextKeyType::STRING,
        'authentication.amr'                   => ContextKeyType::LIST,
        'authentication.auth_time'             => ContextKeyType::NUMBER,
        'authentication.mfa'                   => ContextKeyType::BOOL,
        'authentication.recovery_code'         => ContextKeyType::BOOL,
        'authentication.multifactor'           => ContextKeyType::BOOL,
        'authentication.seconds_since_step_up' => ContextKeyType::NUMBER,
        'authentication.credential'            => ContextKeyType::STRING,
        'authentication.scopes'                => ContextKeyType::LIST,
        'authentication.ip'                    => ContextKeyType::IP,
        'mfa.accepted'                         => ContextKeyType::BOOL,
        'mfa.multifactor'                      => ContextKeyType::BOOL,
        'mfa.factor_types'                     => ContextKeyType::LIST,
        'mfa.level'                            => ContextKeyType::STRING,
        'mfa.phishing_resistant'               => ContextKeyType::BOOL,
        'mfa.user_verification'                => ContextKeyType::BOOL,
        'mfa.last_verification_age_seconds'    => ContextKeyType::NUMBER,
        'mfa.has_confirmed_factor'             => ContextKeyType::BOOL,
        'sso.connection'                       => ContextKeyType::STRING,
        'sso.tenant'                           => ContextKeyType::STRING,
        'sso.protocol'                         => ContextKeyType::STRING,
        'sso.provider_auth_time'               => ContextKeyType::TIME,
        'sso.provider_amr'                     => ContextKeyType::LIST,
        'sso.provider_acr'                     => ContextKeyType::STRING,
        'sso.provider_authn_context_class_ref' => ContextKeyType::STRING,
        'sso.link'                             => ContextKeyType::STRING,
        'sso.link_provenance'                  => ContextKeyType::STRING,
        'sso.provider_session_deadline'        => ContextKeyType::TIME,
        'sso.session_not_after'                => ContextKeyType::TIME,
        'sso.enforcement_version'              => ContextKeyType::STRING,
    ];

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
        foreach (self::KEYS as $path => $type) {

            if ($catalogue->find($path) !== null) {
                continue;
            }

            $catalogue->declare($path, $type);
        }
    }
}
