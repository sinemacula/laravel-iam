<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * How `actingAsCaller()` signs a person in: `started()`, `signedIn()` with
 * credentials, or `throughSso()`.
 *
 * A started session's first factor is on the `unknown` channel, so MFA can
 * verify no level after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class CallerSession
{
    /** @var string The default sign-in method. */
    public const string DEFAULT_METHOD = 'password';

    /** @var string The method an SSO sign-in records. */
    public const string EXTERNAL_METHOD = 'external_provider';

    /**
     * Constructor.
     *
     * @param  string  $method
     * @param  ?\SensitiveParameterValue  $credentials
     * @param  ?\SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     */
    private function __construct(

        /** The sign-in method the session records. */
        public string $method,

        /** The credentials, wrapped so dumps never show them; `null` unless signed in with them. */
        private ?\SensitiveParameterValue $credentials,

        /** SSO's provenance of the session; `null` unless signed in through SSO. */
        public ?Provenance $provenance,
    ) {}

    /**
     * A session started under the method, with no first factor MFA can judge.
     *
     * @param  string  $method
     * @return self
     */
    public static function started(string $method = self::DEFAULT_METHOD): self
    {
        return new self($method, null, null);
    }

    /**
     * A session signed in with credentials that must sign in the acted
     * identity.
     *
     * @param  array<array-key, mixed>  $credentials
     * @param  string  $method
     * @return self
     */
    public static function signedIn(#[\SensitiveParameter] array $credentials, string $method = self::DEFAULT_METHOD): self
    {
        return new self($method, new \SensitiveParameterValue($credentials), null);
    }

    /**
     * A session signed in through SSO; the provenance must name its link.
     *
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return self
     */
    public static function throughSso(Provenance $provenance): self
    {
        return new self(self::EXTERNAL_METHOD, null, $provenance);
    }

    /**
     * The credentials, or `null` unless signed in with them.
     *
     * @return ?array<array-key, mixed>
     */
    public function credentials(): ?array
    {
        /** @var ?array<array-key, mixed> */
        return $this->credentials?->getValue();
    }

    /**
     * Whether MFA can judge the session's first factor.
     *
     * @return bool
     */
    public function provesFirstFactor(): bool
    {
        return $this->credentials !== null || $this->provenance !== null;
    }
}
