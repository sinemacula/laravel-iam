<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Fixtures\Sso\Redemptions;

/**
 * Unit tests for the record of the redemption SSO admitted in this request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdmittedRedemptions::class)]
final class AdmittedRedemptionsTest extends TestCase
{
    /**
     * The redemption answers for exactly its result's connection, issuer,
     * subject and NameID format.
     *
     * @return void
     */
    public function testTheRedemptionAnswersForItsOwnResult(): void
    {
        $admitted   = new AdmittedRedemptions;
        $redemption = Redemptions::signIn();

        $admitted->record($redemption, Redemptions::client());

        self::assertSame($redemption, $admitted->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT));
    }

    /**
     * A sign-in's client is answered for its identity and no session alone.
     *
     * @return void
     */
    public function testASignInsClientIsAnsweredForItsIdentityAndNoSessionAlone(): void
    {
        $admitted = new AdmittedRedemptions;
        $identity = Redemptions::identity();
        $client   = new ClientContext('198.51.100.4', 'sign-in-agent');

        self::assertNull($admitted->clientFor($identity, null));

        $admitted->record(Redemptions::signIn(), $client);

        self::assertSame($client, $admitted->clientFor($identity, null));
        self::assertNull($admitted->clientFor($identity, Redemptions::SESSION));
        self::assertNull($admitted->clientFor(new IdentityReference($identity->type, $identity->id . '0'), null));
        self::assertNull($admitted->clientFor(new IdentityReference('machine', $identity->id), null));

        $admitted->forget();

        self::assertNull($admitted->clientFor($identity, null));
    }

    /**
     * A re-authentication's client is answered for its identity and session
     * alone.
     *
     * @return void
     */
    public function testAReauthenticationsClientIsAnsweredForItsIdentityAndSessionAlone(): void
    {
        $admitted = new AdmittedRedemptions;
        $identity = Redemptions::identity();
        $client   = Redemptions::client();

        $admitted->record(Redemptions::reauthentication(), $client);

        self::assertSame($client, $admitted->clientFor($identity, Redemptions::SESSION));
        self::assertNull($admitted->clientFor($identity, null));
        self::assertNull($admitted->clientFor($identity, Redemptions::SESSION . '0'));
        self::assertNull($admitted->clientFor(new IdentityReference($identity->type, $identity->id . '0'), Redemptions::SESSION));
    }

    /**
     * The next redemption answers its own client, never the one before's.
     *
     * @return void
     */
    public function testTheNextRedemptionAnswersItsOwnClient(): void
    {
        $admitted = new AdmittedRedemptions;
        $next     = new ClientContext(null, null);

        $admitted->record(Redemptions::signIn(), Redemptions::client());
        $admitted->forget();
        $admitted->record(Redemptions::signIn(), $next);

        self::assertSame($next, $admitted->clientFor(Redemptions::identity(), null));
    }

    /**
     * Accepted evidence is answered for its connection and linked identity
     * alone.
     *
     * @return void
     */
    public function testTheAcceptedEvidenceIsAnsweredForItsConnectionAndIdentityAlone(): void
    {
        $admitted   = new AdmittedRedemptions;
        $redemption = Redemptions::signIn();
        $identity   = Redemptions::identity();

        self::assertNull($admitted->acceptedEvidence(Redemptions::CONNECTION, $identity));

        $admitted->record($redemption, Redemptions::client());

        self::assertSame($redemption->evidence, $admitted->acceptedEvidence(Redemptions::CONNECTION, $identity));
        self::assertNull($admitted->acceptedEvidence('connection-2', $identity));
        self::assertNull($admitted->acceptedEvidence(strtoupper(Redemptions::CONNECTION), $identity));
        self::assertNull($admitted->acceptedEvidence(Redemptions::CONNECTION, new IdentityReference($identity->type, $identity->id . '0')));
        self::assertNull($admitted->acceptedEvidence(Redemptions::CONNECTION, new IdentityReference('machine', $identity->id)));

        $admitted->forget();

        self::assertNull($admitted->acceptedEvidence(Redemptions::CONNECTION, $identity));

        $admitted->record(Redemptions::signIn(evidence: false), Redemptions::client());

        self::assertNull($admitted->acceptedEvidence(Redemptions::CONNECTION, $identity));
    }

    /**
     * Results differing from the admitted one in one part.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: ?string}>
     */
    public static function provideOtherResults(): iterable
    {
        yield 'another connection' => ['connection-2', Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT];

        yield 'another issuer' => [Redemptions::CONNECTION, 'https://other.example.test', Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT];

        yield 'another subject' => [Redemptions::CONNECTION, Redemptions::ISSUER, 'subject-2', Redemptions::NAME_ID_FORMAT];

        yield 'a subject in another case' => [Redemptions::CONNECTION, Redemptions::ISSUER, 'SUBJECT-1', Redemptions::NAME_ID_FORMAT];

        yield 'another NameID format' => [Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'];

        yield 'no NameID format' => [Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, null];
    }

    /**
     * A result differing in any way, letter case included, is answered by
     * nothing.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $nameIdFormat
     * @return void
     */
    #[DataProvider('provideOtherResults')]
    public function testAnotherResultIsAnsweredByNothing(string $connectionId, string $issuer, string $subject, ?string $nameIdFormat): void
    {
        $admitted = new AdmittedRedemptions;

        $admitted->record(Redemptions::signIn(), Redemptions::client());

        self::assertNull($admitted->matching($connectionId, $issuer, $subject, $nameIdFormat));
    }

    /**
     * Nothing recorded answers nothing.
     *
     * @return void
     */
    public function testNothingRecordedAnswersNothing(): void
    {
        self::assertNull((new AdmittedRedemptions)->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT));
    }

    /**
     * A redemption forgotten answers nothing, and another may be recorded.
     *
     * @return void
     */
    public function testAForgottenRedemptionAnswersNothing(): void
    {
        $admitted = new AdmittedRedemptions;
        $next     = Redemptions::reauthentication();

        $admitted->record(Redemptions::signIn(), Redemptions::client());
        $admitted->forget();

        self::assertNull($admitted->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT));

        $admitted->record($next, Redemptions::client());

        self::assertSame($next, $admitted->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT));
    }

    /**
     * A second redemption while one is held is a `LogicException`.
     *
     * @return void
     */
    public function testASecondRedemptionIsRefused(): void
    {
        $admitted = new AdmittedRedemptions;
        $first    = Redemptions::signIn();

        $admitted->record($first, Redemptions::client());

        try {
            $admitted->record(Redemptions::reauthentication(), Redemptions::client());

            self::fail('A second redemption was recorded.');
        } catch (\LogicException $exception) {
            self::assertSame('One redemption is admitted at a time: another was recorded while one was held.', $exception->getMessage());
        }

        self::assertSame($first, $admitted->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT));
    }

    /**
     * Redemptions that are not admitted and linked.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Sso\Handoffs\RedemptionResult}>
     */
    public static function provideUnrecordedRedemptions(): iterable
    {
        yield 'refused' => [static fn (): RedemptionResult => RedemptionResult::refused(FailureReason::REPLAYED)];

        yield 'standalone' => [static fn (): RedemptionResult => Redemptions::link()];

        yield 'unlinked' => [static fn (): RedemptionResult => RedemptionResult::redeemed(Redemptions::verified(), linkId: Redemptions::LINK, admitted: true)];

        yield 'with no link' => [static fn (): RedemptionResult => RedemptionResult::redeemed(Redemptions::verified(), new IdentityReference('person', '42'), admitted: true)];
    }

    /**
     * A redemption not admitted, or missing a result, identity or link, is
     * never recorded.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return void
     */
    #[DataProvider('provideUnrecordedRedemptions')]
    public function testOnlyAnAdmittedLinkedRedemptionIsRecorded(\Closure $redemption): void
    {
        $admitted = new AdmittedRedemptions;

        try {
            $admitted->record($redemption(), Redemptions::client());

            self::fail('The redemption was recorded.');
        } catch (\LogicException $exception) {
            self::assertSame('Only a redemption SSO admitted, with the identity and the link it resolved, is recorded.', $exception->getMessage());
        }

        self::assertNull($admitted->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT));
    }
}
