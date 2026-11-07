<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Sso\ExternalResults;
use SineMacula\Laravel\Iam\Sso\Renewal;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Sso\Redemptions;

/**
 * Unit tests for building `laravel-authentication`'s external result from a
 * redemption SSO admitted: every value is the redemption's own, the evidence is
 * what SSO accepted alone, the provider context is the captured provenance's
 * stored form, and a re-authentication's result takes the renewal's time and
 * evidence and carries no provider context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalResults::class)]
final class ExternalResultsTest extends TestCase
{
    /**
     * A sign-in's result takes every value from the redemption: the result's
     * connection, issuer, subject, tenant, provider time and request reference,
     * and the redemption's deadline, enforcement version and link.
     *
     * @return void
     */
    public function testASignInsResultTakesEveryValueFromTheRedemption(): void
    {
        $result = ExternalResults::from(Redemptions::signIn());

        self::assertSame(Redemptions::CONNECTION, $result->connectionId);
        self::assertSame(Redemptions::ISSUER, $result->issuer);
        self::assertSame(Redemptions::SUBJECT, $result->subject);
        self::assertSame(Redemptions::TENANT, $result->tenantId);
        self::assertSame('2026-11-01T09:29:30+00:00', $result->authenticatedAt?->toIso8601String());
        self::assertSame('2026-11-01T17:30:00+00:00', $result->sessionNotAfter?->toIso8601String());
        self::assertSame(Redemptions::ENFORCEMENT, $result->policyVersion);
        self::assertSame(Redemptions::LINK, $result->linkId);
        self::assertSame(Redemptions::REFERENCE, $result->requestReference);
    }

    /**
     * The evidence is what SSO's evidence contract accepted, its methods, raw
     * context and time, never the result's own raw authentication context.
     *
     * @return void
     */
    public function testTheEvidenceIsWhatSsoAccepted(): void
    {
        $evidence = ExternalResults::from(Redemptions::signIn())->evidence;

        self::assertNotNull($evidence);
        self::assertSame(['pwd', 'mfa'], $evidence->methods);
        self::assertSame('urn:example:acr:silver', $evidence->context);
        self::assertSame('2026-11-01T09:29:30+00:00', $evidence->authenticatedAt->toIso8601String());
    }

    /**
     * The provider context is the captured provenance in its stored form,
     * exactly.
     *
     * @return void
     */
    public function testTheProviderContextIsTheCapturedProvenance(): void
    {
        $context = ExternalResults::from(Redemptions::signIn())->providerContext;

        self::assertNotNull($context);
        self::assertSame(Redemptions::provenance()->toArray(), $context->toArray());
    }

    /**
     * A redemption that accepted no evidence and captured no provenance gives
     * the result neither, and one with no provider time gives none.
     *
     * @return void
     */
    public function testWhatTheRedemptionLacksTheResultLacks(): void
    {
        $verified = Redemptions::verified();
        $timeless = RedemptionResult::redeemed(
            result: new VerifiedResult(
                $verified->issuer,
                $verified->subject,
                null,
                $verified->connectionId,
                $verified->tenantId,
                $verified->protocol,
                $verified->application,
                Purpose::SIGN_IN,
                $verified->requestReference,
                [],
                false,
                new AuthenticationContext,
            ),
            linkedIdentity: Redemptions::identity(),
            linkId: Redemptions::LINK,
            admitted: true,
        );

        $result = ExternalResults::from($timeless);

        self::assertNull($result->authenticatedAt);
        self::assertNull($result->sessionNotAfter);
        self::assertNull($result->policyVersion);
        self::assertNull($result->evidence);
        self::assertNull($result->providerContext);
    }

    /**
     * A re-authentication's result takes the renewal's provider time and
     * evidence, the redemption's other values, and no provider context.
     *
     * @return void
     */
    public function testAReauthenticationsResultTakesTheRenewal(): void
    {
        $time     = CarbonImmutable::parse('2026-11-01T09:29:45Z');
        $evidence = new AcceptedEvidence(Redemptions::CONNECTION, $time, ['otp'], null);
        $result   = ExternalResults::renewing(Redemptions::reauthentication(), new Renewal(Redemptions::identity(), Redemptions::SESSION, $time, $evidence));

        self::assertSame(Redemptions::CONNECTION, $result->connectionId);
        self::assertSame(Redemptions::ISSUER, $result->issuer);
        self::assertSame(Redemptions::SUBJECT, $result->subject);
        self::assertSame(Redemptions::TENANT, $result->tenantId);
        self::assertSame('2026-11-01T09:29:45+00:00', $result->authenticatedAt?->toIso8601String());
        self::assertSame('2026-11-01T17:30:00+00:00', $result->sessionNotAfter?->toIso8601String());
        self::assertSame(Redemptions::ENFORCEMENT, $result->policyVersion);
        self::assertSame(Redemptions::LINK, $result->linkId);
        self::assertSame(Redemptions::REFERENCE, $result->requestReference);
        self::assertSame(['otp'], $result->evidence?->methods);
        self::assertNull($result->evidence->context);
        self::assertNull($result->providerContext);
    }

    /**
     * A renewal that accepted no evidence gives the result none, whatever the
     * redemption accepted.
     *
     * @return void
     */
    public function testARenewalWithNoEvidenceGivesNone(): void
    {
        $renewal = new Renewal(Redemptions::identity(), Redemptions::SESSION, CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT), null);

        self::assertNull(ExternalResults::renewing(Redemptions::reauthentication(), $renewal)->evidence);
    }

    /**
     * A redemption that redeemed nothing builds no result, for a sign-in or a
     * re-authentication.
     *
     * @return void
     */
    public function testARefusalBuildsNoResult(): void
    {
        $refused = RedemptionResult::refused(FailureReason::REPLAYED);
        $renewal = new Renewal(Redemptions::identity(), Redemptions::SESSION, CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT), null);

        foreach ([static fn (): mixed => ExternalResults::from($refused), static fn (): mixed => ExternalResults::renewing($refused, $renewal)] as $build) {

            try {
                $build();

                self::fail('A result was built from a refusal.');
            } catch (\LogicException $exception) {
                self::assertSame('An external result is built only from a redemption SSO redeemed.', $exception->getMessage());
            }
        }
    }
}
