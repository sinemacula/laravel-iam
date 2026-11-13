<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;

/**
 * The seams passkeys become MFA factors through; the factor gate stays bound so
 * a withdrawn type's passkeys still remove their factors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeySeams implements ProvidesSeams
{
    /** @var string The MFA factor type passkeys are offered as. */
    public const string TYPE = 'passkey';

    /** @var string The key MFA keeps each application's settings under. */
    private const string APPLICATIONS = 'mfa.applications';

    /**
     * Return the bindings of passkeys as MFA factors.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on = MfaSeams::isOn($config);

        return [
            new SeamBinding(PasskeyGateway::class, PasskeyGatewayAdapter::class, $on && self::isOffered($config)),
            new SeamBinding(PasskeyFactorGate::class, PasskeyFactorGateAdapter::class, $on, mandatory: true),
        ];
    }

    /**
     * Whether any MFA application offers the `passkey` factor type.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isOffered(Repository $config): bool
    {
        $applications = $config->get(self::APPLICATIONS);

        foreach (is_array($applications) ? $applications : [] as $settings) {

            if (self::offersIn($settings)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the named MFA application offers the `passkey` factor type.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $application
     * @return bool
     */
    public static function isOfferedBy(Repository $config, string $application): bool
    {
        $applications = $config->get(self::APPLICATIONS);

        return is_array($applications) && self::offersIn($applications[$application] ?? null);
    }

    /**
     * Whether an application's settings list the `passkey` type.
     *
     * @param  mixed  $settings
     * @return bool
     */
    private static function offersIn(mixed $settings): bool
    {
        $types = is_array($settings) ? $settings['types'] ?? null : null;

        return is_array($types) && in_array(self::TYPE, $types, true);
    }
}
