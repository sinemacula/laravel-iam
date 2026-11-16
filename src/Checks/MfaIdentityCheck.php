<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Checks every person identity model a `jwt` guard uses is MFA's identity while
 * the MFA adapters are on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MfaIdentityCheck implements Check
{
    /** @var string The failure for a person MFA cannot hold factors for. */
    private const string NOT_MFA = 'The identity model %s of a `jwt` guard does not implement %s, so each of its sign-ins throws while `%s` is on.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the switch and the guards are read from. */
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
        return 'identities';
    }

    /**
     * The check applies while the MFA adapters are on.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return MfaSeams::isOn($this->config);
    }

    /**
     * One check per identity model a `jwt` guard uses.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [...array_map(static fn (string $model): \Closure => static fn () => self::assertMfaIdentity($model), StorageCheck::identityModels($this->config, ['jwt']))];
    }

    /**
     * Refuse a person identity model that is not MFA's identity.
     *
     * @param  string  $model
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertMfaIdentity(string $model): void
    {
        if (is_a($model, MultiFactorAuthenticatable::class, true) || is_a($model, MachineIdentity::class, true)) {
            return;
        }

        throw new \LogicException(sprintf(self::NOT_MFA, $model, MultiFactorAuthenticatable::class, MfaSeams::SWITCH));
    }
}
