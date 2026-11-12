<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

/**
 * When an external provider's proof may name its connection to MFA, so a
 * combination policy can trust it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProviderTrust
{
    /**
     * Constructor.
     *
     * @param  bool  $countsAccepted
     * @param  ?string  $tenantId
     */
    private function __construct(

        /** Whether a proof carrying accepted evidence may name its connection at all. */
        public bool $countsAccepted,

        /** The tenant that must trust the connection, or `null` when none acts. */
        public ?string $tenantId,
    ) {}

    /**
     * The provider's proofs never name their connection to MFA.
     *
     * @return self
     */
    public static function withheld(): self
    {
        return new self(false, null);
    }

    /**
     * Name the connection for accepted evidence the tenant, if any, trusts.
     *
     * @param  ?string  $tenantId
     * @return self
     */
    public static function accepted(?string $tenantId): self
    {
        return new self(true, $tenantId);
    }
}
