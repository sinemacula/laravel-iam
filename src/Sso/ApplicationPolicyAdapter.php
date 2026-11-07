<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy as AuthenticationApplicationPolicy;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;

/**
 * SSO's application policy, answered by `laravel-authentication`'s sign-in
 * methods for the application (IAM-4.6, SSO-5.1, SSO-9.2, AUTH-3.7).
 *
 * An SSO application is the guard of the same name, and it allows sign-in
 * through an external provider exactly when `laravel-authentication`'s
 * application policy lets that guard's sessions start by the
 * `external_provider` method (`SignInMethodManager::EXTERNAL_METHOD`), so a
 * flow is never started, nor a handoff code issued, for an application whose
 * external sign-in `laravel-authentication` would refuse at redemption. SSO's
 * own `external_sign_in` setting for the application is not read: one answer,
 * the authentication's, decides.
 *
 * `laravel-authentication`'s policy is asked on every call and reads its
 * configuration then, so a change applies at once; an application that is no
 * guard it knows is its `InvalidArgumentException`, which propagates, since SSO
 * never answers `allowed` when it cannot tell. It keeps nothing between calls
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationPolicyAdapter implements ApplicationPolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     */
    public function __construct(

        /** `laravel-authentication`'s policy of each guard's sign-in methods. */
        private AuthenticationApplicationPolicy $policy,
    ) {}

    /**
     * Whether the application's guard lets a session start through an external
     * provider.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function externalSignIn(Application $application): ExternalSignIn
    {
        return $this->policy->allowsMethod($application->name, SignInMethodManager::EXTERNAL_METHOD)
            ? ExternalSignIn::ALLOWED
            : ExternalSignIn::NOT_ALLOWED;
    }
}
