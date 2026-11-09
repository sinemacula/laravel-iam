<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

/**
 * Declares the keys of the authentication context this package binds
 * (`AuthenticationContextAdapter`) to `laravel-authorization`'s key catalogue
 * (IAM-6.2, AUTHZ-8.2), as the catalogue asks of the context that supplies
 * them: a policy reads only a declared key, so without them no condition could
 * name `laravel-authentication`'s keys, MFA's or SSO's.
 *
 * Each key is declared with the type its member gives its value, and testable:
 * whether a condition may test it is the catalogue's to decide, from the
 * assurance keys the context declares beside `laravel-authorization`'s own
 * (`AuthenticationContextAdapter::ASSURANCE_KEYS`), each of which it makes
 * untestable whatever is declared. `laravel-authorization` learns the types of
 * a context's keys from nothing else, so the types are declared here.
 *
 * A key already declared (by `authorization.context.keys`, an attribute
 * provider, or a service provider that declared it first) is left as it is
 * declared: the application's declaration wins. The keys are declared once, as
 * the catalogue, one per application, is built, and only while the
 * authentication context bound is this package's: one the application binds
 * declares its own.
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
     * Declare the keys on the key catalogue once it is built, while the
     * authentication context bound is this package's.
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
