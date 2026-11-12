<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy as AuthenticationApplicationPolicy;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;

/**
 * SSO's application policy, answered by whether `laravel-authentication` lets
 * the application's guard sign in through an external provider.
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
     * Whether the application's guard allows an external provider's sign-in.
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
