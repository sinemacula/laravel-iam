<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Codes;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * A confirmed delivered factor with no row, so MFA never finds it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DetachedFactor implements Factor // phpcs:ignore SineMacula.Metrics.MaxMethodCount.TooManyMethods
{
    /**
     * Constructor.
     *
     * @param  mixed  $id
     * @param  string  $type
     * @param  ?string  $destination
     */
    public function __construct(

        /** The factor's identifier. */
        private mixed $id = 'detached-factor',

        /** The factor's type. */
        private string $type = 'sms',

        /** Where the factor's codes go. */
        private ?string $destination = '+447700900123',
    ) {}

    /**
     * The factor's identifier.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * The factor's type.
     *
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * No label.
     *
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return null;
    }

    /**
     * Where the factor's codes go.
     *
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return $this->destination;
    }

    /**
     * No credential.
     *
     * @return ?string
     */
    #[\Override]
    public function getCredentialReference(): ?string
    {
        return null;
    }

    /**
     * No secret.
     *
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return null;
    }

    /**
     * No TOTP algorithm.
     *
     * @return ?string
     */
    #[\Override]
    public function getTotpAlgorithm(): ?string
    {
        return null;
    }

    /**
     * No TOTP digits.
     *
     * @return ?int
     */
    #[\Override]
    public function getTotpDigits(): ?int
    {
        return null;
    }

    /**
     * No TOTP period.
     *
     * @return ?int
     */
    #[\Override]
    public function getTotpPeriod(): ?int
    {
        return null;
    }

    /**
     * No accepted step.
     *
     * @return ?int
     */
    #[\Override]
    public function getLastAcceptedStep(): ?int
    {
        return null;
    }

    /**
     * Confirmed.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\FactorStatus
     */
    #[\Override]
    public function getStatus(): FactorStatus
    {
        return FactorStatus::CONFIRMED;
    }

    /**
     * Confirmed.
     *
     * @return bool
     */
    #[\Override]
    public function isConfirmed(): bool
    {
        return true;
    }

    /**
     * Not preferred.
     *
     * @return bool
     */
    #[\Override]
    public function isPreferred(): bool
    {
        return false;
    }

    /**
     * No failures.
     *
     * @return int
     */
    #[\Override]
    public function getConsecutiveFailures(): int
    {
        return 0;
    }

    /**
     * Not disabled.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getDisabledAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Any application.
     *
     * @return ?string
     */
    #[\Override]
    public function getApplication(): ?string
    {
        return null;
    }

    /**
     * Never confirmed at a known time.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getConfirmedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Never used.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastUsedAt(): ?CarbonInterface
    {
        return null;
    }
}
