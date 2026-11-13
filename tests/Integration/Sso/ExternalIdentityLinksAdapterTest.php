<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\ExternalIdentityLinksAdapter;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for the external identity links answered from the
 * redemption SSO admitted in this request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalIdentityLinksAdapter::class)]
final class ExternalIdentityLinksAdapterTest extends TestCase
{
    use MigratesMembers, SignsInPeople, SignsInThroughLinks;

    /**
     * The admitted link answers for exactly the admitted connection, issuer and
     * subject.
     *
     * @return void
     */
    public function testTheAdmittedLinkAnswersForExactlyItsResult(): void
    {
        $person = $this->createPerson();

        $this->admit($person);

        DB::enableQueryLog();

        $link = $this->adapter()->find(self::SSO_CONNECTION, self::ISSUER, self::subjectOf($person));

        self::assertNotNull($link);
        self::assertInstanceOf(Person::class, $link->identity);
        self::assertTrue($person->is($link->identity));
        self::assertSame(self::LINK, $link->id);
        self::assertCount(1, DB::getQueryLog());
        self::assertStringContainsString($person->getTable(), DB::getQueryLog()[0]['query']);
    }

    /**
     * Rows of `[connection, issuer, subject]`, each differing from the admitted
     * result in one part.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?string}>
     */
    public static function provideOtherResults(): iterable
    {
        yield 'another connection' => ['connection-2', self::ISSUER, null];

        yield 'the connection in another case' => ['CONNECTION-1', self::ISSUER, null];

        yield 'another issuer' => [self::SSO_CONNECTION, 'https://idp.example.test/', null];

        yield 'another subject' => [self::SSO_CONNECTION, self::ISSUER, 'subject-0'];
    }

    /**
     * A result differing from the admitted one by a single byte is linked to
     * nothing.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  ?string  $subject
     * @return void
     */
    #[DataProvider('provideOtherResults')]
    public function testAnyOtherResultIsLinkedToNothing(string $connectionId, string $issuer, ?string $subject): void
    {
        $person = $this->createPerson();

        $this->admit($person);

        self::assertNull($this->adapter()->find($connectionId, $issuer, $subject ?? self::subjectOf($person)));
    }

    /**
     * Without an admitted redemption nothing is linked, and no link is looked
     * up.
     *
     * @return void
     */
    public function testNothingIsLinkedWithNoAdmission(): void
    {
        $person  = $this->createPerson();
        $subject = self::subjectOf($person);

        DB::enableQueryLog();

        self::assertNull($this->adapter()->find(self::SSO_CONNECTION, self::ISSUER, $subject));
        self::assertSame([], DB::getQueryLog());

        $this->admit($person)->forget();

        self::assertNull($this->adapter()->find(self::SSO_CONNECTION, self::ISSUER, $subject));

        $this->admit($person);
        $this->app?->forgetScopedInstances();

        self::assertNull($this->adapter()->find(self::SSO_CONNECTION, self::ISSUER, $subject));
    }

    /**
     * An admission that names no link is linked to nothing.
     *
     * @return void
     */
    public function testAnAdmissionNamingNoLinkIsLinkedToNothing(): void
    {
        $person  = $this->createPerson();
        $records = $this->app?->make(AdmittedRedemptions::class);

        self::assertInstanceOf(AdmittedRedemptions::class, $records);

        (new \ReflectionProperty(AdmittedRedemptions::class, 'admitted'))->setValue($records, RedemptionResult::redeemed(
            result: self::verified($person),
            linkedIdentity: self::referenceOf($person),
            admitted: true,
        ));

        self::assertNull($this->adapter()->find(self::SSO_CONNECTION, self::ISSUER, self::subjectOf($person)));
    }

    /**
     * An admitted identity that cannot be resolved throws.
     *
     * @return void
     */
    public function testAnUnresolvedAdmittedIdentityThrows(): void
    {
        $person  = $this->createPerson();
        $records = $this->app?->make(AdmittedRedemptions::class);

        self::assertInstanceOf(AdmittedRedemptions::class, $records);

        $records->record(RedemptionResult::redeemed(
            result: self::verified($person),
            linkedIdentity: new IdentityReference(Person::class, '987654'),
            linkId: self::LINK,
            admitted: true,
        ));

        try {
            $this->adapter()->find(self::SSO_CONNECTION, self::ISSUER, self::subjectOf($person));

            self::fail('An unresolved identity was linked.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        }
    }

    /**
     * An external sign-in signs the admitted identity in through exactly the
     * admitted link.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalSignInGoesThroughTheAdmittedLink(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person);

        $provenance = DB::table('authentication_provenance')->where('session_id', self::keyOf($session))->first();

        self::assertTrue($person->is($session->authenticatable()->getResults()));
        self::assertNotNull($provenance);
        self::assertSame(self::SSO_CONNECTION, $provenance->connection_id);
        self::assertSame(self::LINK, $provenance->link_id);
    }

    /**
     * Rows of `[link, subject, reason]` for results naming another link or
     * subject.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedResults(): iterable
    {
        yield 'another link' => ['link-2', null, FailureReason::LINK_MISMATCH];

        yield 'another subject' => [self::LINK, 'subject-0', FailureReason::EXTERNAL_RESULT_UNLINKED];
    }

    /**
     * A result naming another link or an unadmitted subject signs nobody in.
     *
     * @param  string  $linkId
     * @param  ?string  $subject
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedResults')]
    public function testAnExternalSignInThroughAnyOtherLinkIsRefused(string $linkId, ?string $subject, FailureReason $reason): void
    {
        $person = $this->createPerson();

        $this->admit($person);

        $result = new ExternalResult(self::SSO_CONNECTION, self::ISSUER, $subject ?? self::subjectOf($person), self::SSO_TENANT, linkId: $linkId);
        $answer = $this->sessions()->signInExternally($result, new SignInContext(self::client()));

        self::assertTrue($answer->isFailed());
        self::assertSame($reason, $answer->reason);
        self::assertSame(0, $person->sessions()->count());
    }

    /**
     * The adapter, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\ExternalIdentityLinksAdapter
     */
    private function adapter(): ExternalIdentityLinksAdapter
    {
        $adapter = $this->app?->make(ExternalIdentityLinksAdapter::class);

        self::assertInstanceOf(ExternalIdentityLinksAdapter::class, $adapter);

        return $adapter;
    }
}
