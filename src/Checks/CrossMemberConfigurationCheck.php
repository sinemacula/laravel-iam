<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The configuration that crosses `laravel-authentication`, MFA and SSO holds
 * (IAM-2.5), at deploy.
 *
 * - MFA's applications are `laravel-authentication`'s guards: every key of
 *   `mfa.applications` names a guard in `auth.guards`, since MFA's application
 *   is the guard of the same name (IAM-3.12). A guard with no MFA application
 *   is the application's choice, and enables no factor.
 * - Every operation MFA names (`Mfa\Enums\Operation`) is declared under
 *   `laravel-authentication`'s freshness configuration for each MFA
 *   application's guard, and, while SSO is in use, every operation SSO names
 *   (`Freshness\Enums\FreshnessOperation`) for each SSO application's guard: in
 *   `authentication.freshness`, or in the guard's own `freshness` block, where
 *   `null` removes one. Operations are read as array keys, never as
 *   configuration paths, since their names hold dots.
 *
 * The rest of IAM-2.5 is checked where it belongs, each bullet once: SSO's
 * applications and their unlinked handoffs by `Sso\SsoBridgeCheck`, which SSO's
 * own check runs (IAM-10.3), or `SsoBridgeFallbackCheck` while SSO's check does
 * not; `sso.endpoints.base_url` by SSO's own `EndpointsCheck`;
 * `sso.storage.connection` by the storage alignment, at boot and in
 * `StorageCheck`; audit-log's exclusions, Gate capture and `require_registered`
 * by `AuditCheck`. `laravel-authorization`'s resolvers name this package's
 * adapters only once those adapters exist (M11). Whether a provider attribute
 * lies beyond SSO's standard mapping depends on each connection's mapping,
 * which is a database row, so it is left to the guide, as SSO's routes are.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CrossMemberConfigurationCheck implements Check
{
    /** @var string The key of the application's guards. */
    private const string GUARDS = 'auth.guards';

    /** @var string The key of MFA's applications. */
    private const string MFA_APPLICATIONS = 'mfa.applications';

    /** @var string The key of SSO's applications. */
    private const string SSO_APPLICATIONS = 'sso.applications';

    /** @var string The key of `laravel-authentication`'s freshness operations. */
    private const string FRESHNESS = 'authentication.freshness';

    /** @var string Why an MFA application naming no guard is refused. */
    private const string NO_GUARD = '`%s.%s` names no guard in `%s`: MFA\'s application is the guard of the same name.';

    /** @var string Why a member's operations the guard's freshness does not declare are refused. */
    private const string UNDECLARED = '%s\'s freshness operations [%s] are not declared for guard [%s] under `%s` or the guard\'s `freshness`.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration every member's settings are read from. */
        private Repository $config,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'configuration';
    }

    /**
     * The check always applies: an application with no MFA application and SSO
     * out of use is checked for nothing.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * Every MFA application a guard, then the freshness operations of MFA's
     * applications and, while SSO is in use, of SSO's.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [];

        foreach (self::names($this->config->get(self::MFA_APPLICATIONS)) as $application) {
            $checks[] = fn () => $this->assertGuard($application);
            $checks[] = fn () => $this->assertDeclared($application, array_column(Operation::cases(), 'value'), 'MFA');
        }

        if (!SsoSeams::isInUse($this->config)) {
            return $checks;
        }

        foreach (self::names($this->config->get(self::SSO_APPLICATIONS)) as $application) {
            $checks[] = fn () => $this->assertDeclared($application, array_column(FreshnessOperation::cases(), 'value'), 'SSO');
        }

        return $checks;
    }

    /**
     * Refuse an MFA application that names no guard.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \LogicException
     */
    private function assertGuard(string $application): void
    {
        if (is_array($this->config->get(self::GUARDS . '.' . $application))) {
            return;
        }

        throw new \LogicException(sprintf(self::NO_GUARD, self::MFA_APPLICATIONS, $application, self::GUARDS));
    }

    /**
     * Refuse a member's operations the guard's freshness does not declare.
     *
     * @param  string  $guard
     * @param  list<string>  $operations
     * @param  string  $member
     * @return void
     *
     * @throws \LogicException
     */
    private function assertDeclared(string $guard, array $operations, string $member): void
    {
        $declared = $this->declared($guard);
        $missing  = array_filter($operations, static fn (string $operation): bool => !array_key_exists($operation, $declared));

        if ($missing === []) {
            return;
        }

        throw new \LogicException(sprintf(self::UNDECLARED, $member, implode(', ', $missing), $guard, self::FRESHNESS));
    }

    /**
     * The operations declared for the guard, keyed by name:
     * `laravel-authentication`'s, with the guard's own block over them, where
     * `null` removes one.
     *
     * @param  string  $guard
     * @return array<array-key, mixed>
     */
    private function declared(string $guard): array
    {
        $global    = $this->config->get(self::FRESHNESS);
        $overrides = $this->config->get(self::GUARDS . '.' . $guard . '.freshness');
        $merged    = array_replace(is_array($global) ? $global : [], is_array($overrides) ? $overrides : []);

        return array_filter($merged, static fn (mixed $entry): bool => $entry !== null);
    }

    /**
     * The application names a map of applications keys, none when it is no map.
     *
     * @param  mixed  $applications
     * @return list<string>
     */
    private static function names(mixed $applications): array
    {
        return is_array($applications) ? array_map(strval(...), array_keys($applications)) : [];
    }
}
