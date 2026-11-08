<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * How `Concerns\InteractsWithIam::actingAsCaller()` signs a person in: the
 * session's sign-in method and the first factor it records.
 *
 * Three ways, one of them per caller:
 *
 * - `started()` starts the session for the identity as
 *   `laravel-authentication`'s `start()` does for an identity the application
 *   verified itself, under the method named: the first proof names the method,
 *   but no channel and no `amr` value, so MFA can judge no first factor, and no
 *   level can be verified after it. The default, for a test that needs a
 *   session and no MFA state.
 * - `signedIn()` signs in with the credentials given, through the method named,
 *   as a sign-in endpoint does, so the first proof is the one the method proves
 *   (the password's channel, say), which MFA judges, so a level can be verified
 *   after it.
 * - `throughSso()` signs in through SSO with SSO's provenance, as
 *   `Iam::signIns()` signs in a person whose redemption SSO admitted, under
 *   `external_provider`, so the session records the provenance's connection and
 *   link and its provider context, and its first proof is the provider's.
 *
 * The credentials are held wrapped, so a dump or a stack trace never shows
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class CallerSession
{
    /** @var string The method a session is started or signed in under when none is named. */
    public const string DEFAULT_METHOD = 'password';

    /** @var string The method a session through SSO is signed in under. */
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

        /** The credentials the method verifies, wrapped; `null` unless signed in with them. */
        private ?\SensitiveParameterValue $credentials,

        /** SSO's provenance of the session; `null` unless signed in through SSO. */
        public ?Provenance $provenance,
    ) {}

    /**
     * A session started for the identity under the method, its first factor
     * unattested.
     *
     * @param  string  $method
     * @return self
     */
    public static function started(string $method = self::DEFAULT_METHOD): self
    {
        return new self($method, null, null);
    }

    /**
     * A session signed in with the credentials, through the method, which must
     * sign in the very identity acted as.
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
     * A session signed in through SSO, with SSO's provenance of it, which must
     * name the link it was admitted through.
     *
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return self
     */
    public static function throughSso(Provenance $provenance): self
    {
        return new self(self::EXTERNAL_METHOD, null, $provenance);
    }

    /**
     * The credentials the method verifies, or `null` unless the session is
     * signed in with them.
     *
     * @return ?array<array-key, mixed>
     */
    public function credentials(): ?array
    {
        /** @var ?array<array-key, mixed> */
        return $this->credentials?->getValue();
    }

    /**
     * Whether the session's first proof is one MFA can judge: one a method
     * proved from credentials, or the provider's, through SSO.
     *
     * @return bool
     */
    public function provesFirstFactor(): bool
    {
        return $this->credentials !== null || $this->provenance !== null;
    }
}
