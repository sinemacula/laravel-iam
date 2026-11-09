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
 * Each key is declared with the type its member gives its value. A key that
 * says how strongly or how recently the session was authenticated is declared
 * untestable, as `laravel-authorization` declares its own assurance keys
 * (`amr`, `auth_time`, `multifactor`, `seconds_since_step_up`, which it makes
 * untestable whatever is declared), so a policy states an authentication
 * requirement instead, which the requirement checker judges on the newest proof
 * meeting each part (`RequirementCheckerAdapter`): `laravel-authentication`'s
 * `mfa` and `recovery_code`, MFA's verdicts on the session's evidence
 * (`accepted`, `factor_types`, `level`, `phishing_resistant`,
 * `user_verification`, `last_verification_age_seconds`) and SSO's record of the
 * provider's authentication (`provider_auth_time`, `provider_amr`,
 * `provider_acr`, `provider_authn_context_class_ref`). Every other key may be
 * tested.
 *
 * A key already declared (by `authorization.context.keys`, an attribute
 * provider, or a service provider that declared it first) is left as it is
 * declared: the application's declaration wins. The keys are declared once, as
 * the catalogue, one per application, is built, and only while the
 * authentication context bound is this package's: one the application binds
 * declares its own. A catalogue built before this package bound its context
 * again over `laravel-authorization`'s default has them declared once it has
 * (`declareOnResolved()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationContextKeys
{
    /** @var array<string, array{\SineMacula\Laravel\Authorization\Enums\ContextKeyType, bool}> Each key declared, by its dot path, with its type and whether a condition may test it. */
    public const array KEYS = [
        'authentication.subject_type'          => [ContextKeyType::STRING, true],
        'authentication.identity_type'         => [ContextKeyType::STRING, true],
        'authentication.identity_id'           => [ContextKeyType::STRING, true],
        'authentication.principal_type'        => [ContextKeyType::STRING, true],
        'authentication.principal_id'          => [ContextKeyType::STRING, true],
        'authentication.tenant_type'           => [ContextKeyType::STRING, true],
        'authentication.tenant_id'             => [ContextKeyType::STRING, true],
        'authentication.application'           => [ContextKeyType::STRING, true],
        'authentication.session_id'            => [ContextKeyType::STRING, true],
        'authentication.amr'                   => [ContextKeyType::LIST, false],
        'authentication.auth_time'             => [ContextKeyType::NUMBER, false],
        'authentication.mfa'                   => [ContextKeyType::BOOL, false],
        'authentication.recovery_code'         => [ContextKeyType::BOOL, false],
        'authentication.multifactor'           => [ContextKeyType::BOOL, false],
        'authentication.seconds_since_step_up' => [ContextKeyType::NUMBER, false],
        'authentication.credential'            => [ContextKeyType::STRING, true],
        'authentication.scopes'                => [ContextKeyType::LIST, true],
        'authentication.ip'                    => [ContextKeyType::IP, true],
        'mfa.accepted'                         => [ContextKeyType::BOOL, false],
        'mfa.multifactor'                      => [ContextKeyType::BOOL, false],
        'mfa.factor_types'                     => [ContextKeyType::LIST, false],
        'mfa.level'                            => [ContextKeyType::STRING, false],
        'mfa.phishing_resistant'               => [ContextKeyType::BOOL, false],
        'mfa.user_verification'                => [ContextKeyType::BOOL, false],
        'mfa.last_verification_age_seconds'    => [ContextKeyType::NUMBER, false],
        'mfa.has_confirmed_factor'             => [ContextKeyType::BOOL, true],
        'sso.connection'                       => [ContextKeyType::STRING, true],
        'sso.tenant'                           => [ContextKeyType::STRING, true],
        'sso.protocol'                         => [ContextKeyType::STRING, true],
        'sso.provider_auth_time'               => [ContextKeyType::TIME, false],
        'sso.provider_amr'                     => [ContextKeyType::LIST, false],
        'sso.provider_acr'                     => [ContextKeyType::STRING, false],
        'sso.provider_authn_context_class_ref' => [ContextKeyType::STRING, false],
        'sso.link'                             => [ContextKeyType::STRING, true],
        'sso.link_provenance'                  => [ContextKeyType::STRING, true],
        'sso.provider_session_deadline'        => [ContextKeyType::TIME, true],
        'sso.session_not_after'                => [ContextKeyType::TIME, true],
        'sso.enforcement_version'              => [ContextKeyType::STRING, true],
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
     * Declare the keys on the key catalogue already built, while the
     * authentication context bound is this package's: a catalogue built while
     * `laravel-authorization`'s own default context was bound, before this
     * package bound the adapter over it again, was passed over as it was built
     * (`IamServiceProvider`), and is kept for the life of the process. A
     * catalogue not built yet is left to be declared on as it is.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Psr\Container\ContainerExceptionInterface
     */
    public static function declareOnResolved(Container $container): void
    {
        if (!$container->resolved(ContextKeyCatalogue::class) || !self::isAdapterBound($container)) {
            return;
        }

        self::declareOn($container->make(ContextKeyCatalogue::class));
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
        foreach (self::KEYS as $path => [$type, $isTestable]) {

            if ($catalogue->find($path) !== null) {
                continue;
            }

            $catalogue->declare($path, $type, $isTestable);
        }
    }
}
