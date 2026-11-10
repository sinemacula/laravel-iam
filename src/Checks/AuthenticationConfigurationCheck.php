<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Console\ConfigurationFinding;
use SineMacula\Laravel\Authentication\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Iam\Checks\Contracts\AuthenticationCheck;

/**
 * Reports this package's checks of `laravel-authentication`'s side in
 * `authentication:check` (IAM-10.3), through the registration point
 * `laravel-authentication` offers for them (`Console\ConfigurationChecks`), so
 * the command run at deploy on its own reports them too.
 *
 * It runs the parts of this package's own checks that concern
 * `laravel-authentication` (`Contracts\AuthenticationCheck`), never a copy of
 * them: the mandatory seams that are its contracts, the namespaces of its
 * authentication context and the tenant resolver, about no one guard; and, for
 * each guard the command checks (those named with `--guard`, otherwise every
 * `jwt` and `api_key` guard), the identity model it signs people in through and
 * the MFA and SSO applications of the same name. Each is graded as `iam:check`
 * grades it: a closure that throws is an error, its message the problem, and a
 * note is a warning. Each message is prefixed with the check's subject, as
 * `[iam:<subject>]`, the command prefixing the guard.
 *
 * A check that cannot be resolved, or whose closures cannot be built, is
 * reported as an error naming its class and the class of the exception, never
 * the exception's message, as `laravel-authentication` reports a check that
 * throws, and the checks after it still run. Each check reads configuration and
 * the container only, and names keys, seams, guards and classes, never a value
 * that could be a secret.
 *
 * While `iam:check` runs the members' commands (`Checker::RUNNING`), it answers
 * nothing: `iam:check` reports the same checks under `iam`, so each problem is
 * reported once.
 *
 * Registered from this package's `boot()` as `laravel-authentication`'s checks
 * are resolved, so nothing is registered while its provider has not registered,
 * or where it offers no registration point.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationConfigurationCheck implements ConfigurationCheck
{
    /** @var list<class-string<\SineMacula\Laravel\Iam\Checks\Contracts\AuthenticationCheck>> The checks run, in the order `iam:check` runs them. */
    public const array CHECKS = [
        StorageCheck::class,
        MandatorySeamsCheck::class,
        ContextNamespacesCheck::class,
        CrossMemberConfigurationCheck::class,
    ];

    /** @var string The message of a check that failed to run. */
    private const string FAILED = 'The check [%s] failed: %s.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the checks are resolved from. */
        private Container $container,
    ) {}

    /**
     * The findings of every check about no one guard, then about each guard,
     * none while `iam:check` runs the members' commands.
     *
     * @param  list<string>  $guards
     * @return list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     */
    #[\Override]
    public function findings(array $guards): array
    {
        if ($this->isIamCheckRunning()) {
            return [];
        }

        $findings = [];

        foreach (self::CHECKS as $class) {
            $findings = [...$findings, ...$this->findingsOf($class, $guards)];
        }

        return $findings;
    }

    /**
     * Whether `iam:check` is running the members' commands.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isIamCheckRunning(): bool
    {
        return $this->container->bound(Checker::RUNNING) && $this->container->make(Checker::RUNNING) === true;
    }

    /**
     * The findings of one check, or the error that it could not be run.
     *
     * @param  class-string<\SineMacula\Laravel\Iam\Checks\Contracts\AuthenticationCheck>  $class
     * @param  list<string>  $guards
     * @return list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     */
    private function findingsOf(string $class, array $guards): array
    {
        try {
            $check = $this->container->make($class);

            if (!$check->applies()) {
                return [];
            }

            $closures = [[null, $check->authenticationChecks()]];

            foreach ($guards as $guard) {
                $closures[] = [$guard, $check->guardChecks($guard)];
            }
        } catch (\Throwable $exception) {
            return [ConfigurationFinding::error(sprintf(self::FAILED, $class, $exception::class))];
        }

        $findings = [];

        foreach ($closures as [$guard, $checks]) {
            $findings = [...$findings, ...self::run($check, $checks, $guard)];
        }

        return $findings;
    }

    /**
     * Run every closure, answering an error for each that threw and a warning
     * for each note, about the guard.
     *
     * @param  \SineMacula\Laravel\Iam\Checks\Contracts\AuthenticationCheck  $check
     * @param  list<\Closure(): mixed>  $closures
     * @param  ?string  $guard
     * @return list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     */
    private static function run(AuthenticationCheck $check, array $closures, ?string $guard): array
    {
        $findings = [];
        $prefix   = sprintf('[iam:%s] ', $check->subject());

        foreach ($closures as $closure) {

            try {
                $note = $closure();
            } catch (\Throwable $exception) {
                $findings[] = ConfigurationFinding::error($prefix . $exception->getMessage(), $guard);

                continue;
            }

            if (!is_string($note) || $note === '') {
                continue;
            }

            $findings[] = ConfigurationFinding::warning($prefix . $note, $guard);
        }

        return $findings;
    }
}
