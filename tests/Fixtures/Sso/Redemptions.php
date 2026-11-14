<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * Builds the redemptions SSO answers, for unit tests of what is built from one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Redemptions
{
    /** @var string The connection every result comes through. */
    public const string CONNECTION = 'connection-1';

    /** @var string The issuer every result asserts. */
    public const string ISSUER = 'https://idp.example.test';

    /** @var string The subject every result asserts. */
    public const string SUBJECT = 'subject-1';

    /** @var string The format of the SAML NameID every subject is. */
    public const string NAME_ID_FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /** @var string The tenant the connection belongs to. */
    public const string TENANT = 'tenant-1';

    /** @var string The application every flow is for. */
    public const string APPLICATION = 'api';

    /** @var string The link every redemption resolves through. */
    public const string LINK = 'link-1';

    /** @var string The session a re-authentication is started on. */
    public const string SESSION = 'session-1';

    /** @var string The enforcement version judged under the locks. */
    public const string ENFORCEMENT = 'enforcement-7';

    /** @var string The request reference every result answers. */
    public const string REFERENCE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    /** @var string When the provider authenticated the person. */
    public const string AUTHENTICATED_AT = '2026-11-01T09:29:30.250000Z';

    /** @var string The session's latest end. */
    public const string NOT_AFTER = '2026-11-01T17:30:00Z';

    /**
     * The client every redemption is made for, as SSO is handed it.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    public static function client(): ClientContext
    {
        return new ClientContext('203.0.113.7', 'redemption-agent');
    }

    /**
     * The identity every result links to.
     *
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    public static function identity(): IdentityReference
    {
        return new IdentityReference('person', '42');
    }

    /**
     * The verified result of the purpose, asserting the issuer and subject
     * given.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $issuer
     * @param  string  $subject
     * @param  string  $connectionId
     * @param  ?\Carbon\CarbonImmutable  $authenticatedAt
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    public static function verified(
        Purpose $purpose = Purpose::SIGN_IN,
        string $issuer = self::ISSUER,
        string $subject = self::SUBJECT,
        string $connectionId = self::CONNECTION,
        ?CarbonImmutable $authenticatedAt = null,
    ): VerifiedResult {
        return new VerifiedResult(
            $issuer,
            $subject,
            self::NAME_ID_FORMAT,
            $connectionId,
            self::TENANT,
            'saml2',
            self::APPLICATION,
            $purpose,
            RequestReference::fromString(self::REFERENCE),
            ['email' => 'ada@example.test'],
            false,
            new AuthenticationContext($authenticatedAt ?? CarbonImmutable::parse(self::AUTHENTICATED_AT), ['pwd', 'unregistered'], 'raw-acr-of-the-result'),
        );
    }

    /**
     * What SSO's evidence contract accepted.
     *
     * @return \SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     */
    public static function evidence(): AcceptedEvidence
    {
        return new AcceptedEvidence(self::CONNECTION, CarbonImmutable::parse(self::AUTHENTICATED_AT), ['pwd', 'mfa'], 'urn:example:acr:silver');
    }

    /**
     * The provenance SSO captured of an admitted sign-in.
     *
     * @return \SineMacula\Laravel\Sso\Sessions\Provenance
     */
    public static function provenance(): Provenance
    {
        return new Provenance(
            self::CONNECTION,
            self::TENANT,
            'oidc',
            CarbonImmutable::parse(self::AUTHENTICATED_AT),
            ['pwd', 'mfa'],
            'urn:example:acr:silver',
            null,
            self::LINK,
            LinkOrigin::LINK_PURPOSE,
            CarbonImmutable::parse(self::NOT_AFTER),
            CarbonImmutable::parse(self::NOT_AFTER),
            self::ENFORCEMENT,
        );
    }

    /**
     * An admitted, linked `sign_in`, with or without its evidence and
     * provenance.
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  bool  $evidence
     * @param  bool  $provenance
     * @param  ?string  $linkId
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    public static function signIn(?VerifiedResult $result = null, bool $evidence = true, bool $provenance = true, ?string $linkId = self::LINK): RedemptionResult
    {
        return RedemptionResult::redeemed(
            result: $result ?? self::verified(),
            linkedIdentity: self::identity(),
            enforcementVersion: self::ENFORCEMENT,
            sessionNotAfter: CarbonImmutable::parse(self::NOT_AFTER),
            linkId: $linkId,
            evidence: $evidence ? self::evidence() : null,
            admitted: true,
            provenance: $provenance ? self::provenance() : null,
        );
    }

    /**
     * An admitted `reauthenticate` of the session, with no provenance.
     *
     * @param  bool  $evidence
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    public static function reauthentication(bool $evidence = true): RedemptionResult
    {
        return RedemptionResult::redeemed(
            result: self::verified(Purpose::REAUTHENTICATE),
            linkedIdentity: self::identity(),
            identity: self::identity(),
            sessionId: self::SESSION,
            enforcementVersion: self::ENFORCEMENT,
            sessionNotAfter: CarbonImmutable::parse(self::NOT_AFTER),
            linkId: self::LINK,
            evidence: $evidence ? self::evidence() : null,
            admitted: true,
        );
    }

    /**
     * A `link` redeemed standalone: redeemed, never admitted.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    public static function link(): RedemptionResult
    {
        return RedemptionResult::redeemed(
            result: self::verified(Purpose::LINK),
            linkedIdentity: self::identity(),
            identity: self::identity(),
            linkId: self::LINK,
        );
    }
}
