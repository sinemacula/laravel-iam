<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Passkeys\NoPasskeyFactors;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;

/**
 * The seams passkeys become MFA factors through (IAM-3.10): MFA's passkey
 * gateway runs its ceremonies through `laravel-authentication`'s passkeys, and
 * `laravel-authentication`'s passkey factor gate calls MFA's passkey change
 * gate inside the passkey transaction.
 *
 * MFA's passkey gateway binds only while MFA's capability switch
 * (`iam.adapters.mfa`) is on and an MFA application offers the `passkey` factor
 * type (`mfa.applications.*.types`), read from the configuration every member
 * will hold once registered; otherwise MFA keeps its own default, and no
 * ceremony runs (IAM-1.3). The passkey factor gate binds, and is mandatory,
 * whenever the switch is on, whether or not the type is offered now: a passkey
 * enrolled as a factor while the type was offered stays one once it is
 * withdrawn, and left on `laravel-authentication`'s default, removing it would
 * leave its factor and association standing. MFA's change gate asks nothing of
 * a registration without a binding or of an application that does not enable
 * passkeys, and removes nothing for a credential with no association, so the
 * gate changes nothing else while the type is not offered. Each adapter
 * replaces the member's own default only (IAM-8.4), and is transient (IAM-8.1).
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
     * Return the bindings of passkeys as MFA factors: the passkey gateway on
     * while MFA's capability switch is and an MFA application offers passkeys,
     * and the passkey factor gate on, and mandatory, while the switch is.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $offered = static fn (Repository $switches): bool => MfaSeams::isOn($switches) && self::isOffered($switches);

        return [
            new SeamBinding(PasskeyGateway::class, PasskeyGatewayAdapter::class, [UnavailablePasskeyGateway::class], appliesWhen: $offered),
            new SeamBinding(PasskeyFactorGate::class, PasskeyFactorGateAdapter::class, [NoPasskeyFactors::class], appliesWhen: MfaSeams::isOn(...), mandatory: true),
        ];
    }

    /**
     * Whether any MFA application offers the `passkey` factor type. An
     * application's settings or types that are not a list are read as offering
     * nothing, as MFA's own configuration check refuses them.
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
     * Whether the MFA application of the given name offers the `passkey` factor
     * type, read as `isOffered()` reads every application's.
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
     * Whether an application's settings list the `passkey` factor type among
     * its types.
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
