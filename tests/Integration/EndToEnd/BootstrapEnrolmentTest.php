<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Mfa\Pending\Concerns\ArrangesPendingSessions;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * End-to-end tests of a first factor enrolled from a pending sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessionResolverAdapter::class)]
#[CoversClass(PendingCompletionAdapter::class)]
final class BootstrapEnrolmentTest extends TestCase
{
    use ArrangesPendingSessions;

    /** @var string The tenant that requires a further factor. */
    private const string TENANT = 'tenant-1';

    /**
     * Let everyone act in every tenant, and have the tenant ask for a factor.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        ScriptedTenantRequirement::bind($this->app)->require(self::TENANT, Requirement::none()->withAdditionalVerification());
    }

    /**
     * A TOTP factor enrolled from a pending sign-in activates it in the tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATotpEnrolledFromAPendingSignInActivatesItInTheTenant(): void
    {
        $person  = $this->createPerson();
        $pending = $this->signInTo($person);

        self::assertTrue($pending->isPending(), (string) $pending->reason?->value);

        $credential = $pending->credential?->reveal() ?? self::fail('The pending sign-in carries no credential.');
        $start      = Mfa::startEnrollment(self::servedCaller(self::requestCarrying($credential)), EnrollmentRequest::totp($person->email));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);

        $factor       = Factor::query()->sole();
        $confirmation = Mfa::confirmEnrollment(self::servedCaller(self::requestCarrying($credential)), $start->grant, AuthenticatorApp::code($factor));
        $completion   = $confirmation->verification?->completion();

        self::assertTrue($confirmation->isConfirmed(), (string) $confirmation->reason?->value);
        self::assertNull($confirmation->completion());
        self::assertInstanceOf(SignInResult::class, $completion);
        self::assertTrue($completion->isSignedIn(), (string) $completion->reason?->value);

        $session = $completion->session->record ?? self::fail('No session was signed in.');

        self::assertSame($pending->pending?->session->getKey(), $session->getKey());
        self::assertSame(self::TENANT, $session->getTenantId());

        $proofs = array_map(static fn (RecordedProof $proof): array => [$proof->kind, $proof->factor, $proof->purpose], $this->proofsOf($session));

        self::assertSame([[ProofKind::ADDITIONAL_FACTOR, $factor->id, Purpose::ENROLLMENT], [ProofKind::FIRST_FACTOR, null, Purpose::SIGN_IN]], $proofs);
    }

    /**
     * Let the application's pending sign-ins enrol a first TOTP factor.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = $app->make('config');

        $config->set('mfa.applications.' . self::GUARD . '.requirement', 'never');
        $config->set('mfa.applications.' . self::GUARD . '.bootstrap', ['enabled' => true, 'types' => ['totp']]);
    }

    /**
     * The person's password sign-in to the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInTo(Person $person): SignInResult
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));

        return $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);
    }
}
