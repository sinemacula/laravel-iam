<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

/**
 * When MFA may see an external provider's proof naming the connection it was
 * made through (IAM-4.6, IAM-5.1).
 *
 * A combination policy can trust a provider only by its connection, so a proof
 * that names one is a proof MFA may count as the provider's assurance. The
 * provider's evidence counts only through both gates, SSO's evidence contract
 * and MFA's combination policy, and, for a tenant, only from a connection the
 * tenant trusts; so a proof `laravel-authentication` recorded reaches MFA
 * naming its connection only when this says so:
 *
 * - `withheld()` never: the provider's proofs reach MFA on an
 *   `external_provider` channel naming no connection, which no policy can trust
 *   by its connection. `laravel-authentication`'s requirement check is asked
 *   so, since `laravel-authentication` asks its external evidence policy first,
 *   with the tenant whose requirement it is, and the check is told neither that
 *   tenant nor whether SSO accepted anything;
 * - `accepted()` only when the proof carries evidence SSO's evidence contract
 *   accepted (`RecordedProof::$evidence`), and, for a session acting in a
 *   tenant, only when that tenant trusts the connection (`ConnectionTrust`).
 *   MFA's own judgements of a session, its route gate among them, are asked so,
 *   with the session's tenant, which is the tenant MFA's requirement is for.
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
     * The provider's proofs name their connection to MFA only when they carry
     * accepted evidence and the tenant given, if any, trusts the connection.
     *
     * @param  ?string  $tenantId
     * @return self
     */
    public static function accepted(?string $tenantId): self
    {
        return new self(true, $tenantId);
    }
}
