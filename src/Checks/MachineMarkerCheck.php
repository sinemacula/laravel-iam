<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;

/**
 * Checks every machine identity model carries laravel-authorization's machine
 * marker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MachineMarkerCheck implements Check
{
    /** @var string The failure for a machine without the marker. */
    private const string UNMARKED = 'The identity model %s implements %s without %s, so laravel-authorization takes it for a person.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the guards' providers are read from. */
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
        return 'machines';
    }

    /**
     * The check always applies.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * One check per identity model a `jwt` or `api_key` guard uses.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [...array_map(static fn (string $model): \Closure => static fn () => self::assertMarked($model), StorageCheck::identityModels($this->config))];
    }

    /**
     * Refuse a machine identity model without the machine marker.
     *
     * @param  string  $model
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertMarked(string $model): void
    {
        if (!is_a($model, MachineIdentity::class, true) || is_a($model, AuthorizableMachine::class, true)) {
            return;
        }

        throw new \LogicException(sprintf(self::UNMARKED, $model, MachineIdentity::class, AuthorizableMachine::class));
    }
}
