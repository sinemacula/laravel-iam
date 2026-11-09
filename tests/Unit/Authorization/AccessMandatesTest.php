<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Iam\Authorization\AccessMandates;

/**
 * Unit tests for when `laravel-authentication`'s scope registry and application
 * access are mandatory: the registry while any guard accepts a machine
 * credential, its own methods read over `laravel-authentication`'s default as
 * `laravel-authentication` reads them, or as the bound application policy
 * answers where one is bound, and application access while
 * `authorization.application_access` maps an application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessMandates::class)]
final class AccessMandatesTest extends TestCase
{
    /**
     * Rows of `[configuration, whether a guard accepts a machine credential]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideGuardConfigurations(): iterable
    {
        yield 'no guards' => [[], false];

        yield 'guards that are no list' => [['auth' => ['guards' => 'api']], false];

        yield 'a guard of passwords alone' => [self::guards(['api' => ['application' => ['methods' => ['password']]]]), false];

        $guards = ['api' => ['application' => ['methods' => ['password']]], 'keys' => ['application' => ['methods' => ['api_key']]]];

        yield 'a guard accepting API keys' => [self::guards($guards), true];

        yield 'a guard accepting client credentials' => [self::guards(['api' => ['application' => ['methods' => ['client_credentials']]]]), true];

        yield 'a guard with no methods of its own, over a default accepting API keys' => [self::guards(['keys' => ['driver' => 'api_key']], ['api_key']), true];

        yield 'a guard with no application block, over a default of passwords' => [self::guards(['api' => ['driver' => 'jwt']], ['password']), false];

        yield 'a guard listing no methods, over a default accepting API keys' => [self::guards(['api' => ['application' => ['methods' => []]]], ['api_key']), false];

        yield 'a guard whose methods are null, over a default accepting API keys' => [self::guards(['api' => ['application' => ['methods' => null]]], ['api_key']), false];

        yield 'a guard whose application block is no list, over a default accepting API keys' => [self::guards(['api' => ['application' => 'api_key']], ['api_key']), true];

        yield 'a guard that is no list, over a default accepting client credentials' => [self::guards(['api' => 'jwt'], ['client_credentials']), true];

        yield 'a default that is no list' => [self::guards(['api' => ['driver' => 'jwt']], 'api_key'), false];

        yield 'methods that are no names' => [self::guards(['api' => ['application' => ['methods' => [['api_key'], 7]]]]), false];
    }

    /**
     * The scope registry is mandatory while any guard accepts an API key or a
     * client credentials exchange, its own methods read over
     * `laravel-authentication`'s default.
     *
     * @param  array<string, mixed>  $configuration
     * @param  bool  $accepts
     * @return void
     */
    #[DataProvider('provideGuardConfigurations')]
    public function testTheScopeRegistryIsMandatoryWhileAGuardAcceptsAMachineCredential(array $configuration, bool $accepts): void
    {
        self::assertSame($accepts, AccessMandates::acceptsMachineCredentials(new Repository($configuration)));
    }

    /**
     * With a container handed in that binds an application policy, the policy
     * says which machine credentials each configured guard accepts, whatever
     * its configured methods list: a guard it lets accept an API key or a
     * client credentials exchange makes the registry mandatory, and a guard
     * whose settings it refuses accepts nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheBoundApplicationPolicySaysWhichMachineCredentialsAGuardAccepts(): void
    {
        $config = new Repository(self::guards(['api' => ['application' => ['methods' => ['api_key']]], 'keys' => ['driver' => 'api_key']]));

        self::assertTrue(AccessMandates::acceptsMachineCredentials($config, new Container));

        self::assertFalse(AccessMandates::acceptsMachineCredentials($config, self::policyAccepting([])));
        self::assertTrue(AccessMandates::acceptsMachineCredentials($config, self::policyAccepting(['keys' => 'api_key'])));
        self::assertTrue(AccessMandates::acceptsMachineCredentials($config, self::policyAccepting(['keys' => 'client_credentials'])));
        self::assertFalse(AccessMandates::acceptsMachineCredentials($config, self::policyAccepting(['keys' => 'password'])));

        $refusing = self::createStub(ApplicationPolicy::class);

        $refusing->method('allowsMethod')->willReturnCallback(static fn (string $guard, string $method): bool => $method === 'client_credentials' || self::refuseSettings());

        $container = new Container;

        $container->instance(ApplicationPolicy::class, $refusing);

        self::assertFalse(AccessMandates::acceptsMachineCredentials($config, $container));
    }

    /**
     * Rows of `[application access, whether it maps an application]`.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideApplicationAccess(): iterable
    {
        yield 'unset' => [null, false];

        yield 'empty' => [[], false];

        yield 'no list' => ['admin:access', false];

        yield 'one application mapped' => [['admin' => 'admin:access'], true];
    }

    /**
     * Application access is mandatory while `authorization.application_access`
     * maps an application to the permission to use it.
     *
     * @param  mixed  $access
     * @param  bool  $names
     * @return void
     */
    #[DataProvider('provideApplicationAccess')]
    public function testApplicationAccessIsMandatoryWhileAnApplicationIsMapped(mixed $access, bool $names): void
    {
        self::assertSame($names, AccessMandates::namesApplicationAccess(new Repository(['authorization' => ['application_access' => $access]])));
    }

    /**
     * Refuse a guard's settings, as `laravel-authentication`'s policy refuses a
     * guard whose `application` block is not set.
     *
     * @return never
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseSettings(): never
    {
        throw new \InvalidArgumentException('The guard\'s application settings are not set.');
    }

    /**
     * A container binding an application policy that accepts each guard's one
     * method given, and no other.
     *
     * @param  array<string, string>  $methods
     * @return \Illuminate\Container\Container
     */
    private static function policyAccepting(array $methods): Container
    {
        $policy = self::createStub(ApplicationPolicy::class);

        $policy->method('allowsMethod')->willReturnCallback(static fn (string $guard, string $method): bool => ($methods[$guard] ?? null) === $method);

        $container = new Container;

        $container->instance(ApplicationPolicy::class, $policy);

        return $container;
    }

    /**
     * The configuration of the guards given, over `laravel-authentication`'s
     * default methods given, when any.
     *
     * @param  array<string, mixed>  $guards
     * @param  mixed  $default
     * @return array<string, mixed>
     */
    private static function guards(array $guards, mixed $default = []): array
    {
        return [
            'auth'           => ['guards' => $guards],
            'authentication' => ['application' => ['methods' => $default]],
        ];
    }
}
