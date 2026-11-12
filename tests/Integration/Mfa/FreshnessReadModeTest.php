<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\FreshnessGateAdapter;
use SineMacula\Laravel\Iam\Mfa\ReauthenticatorAdapter;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RecordsFreshnessReadModes;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for the read mode adapters ask the freshness policy in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessGateAdapter::class)]
#[CoversClass(ReauthenticatorAdapter::class)]
#[CoversClass(CurrentSession::class)]
final class FreshnessReadModeTest extends TestCase
{
    use InteractsWithIam, MigratesMembers, RecordsFreshnessReadModes, SignsInPeople;

    /** @var string The route MFA's gate lets a session through only while it is fresh for adding a factor. */
    private const string FRESH_ROUTE = '/fresh/add-factor';

    /** @var string The operation the route and the questions ask about. */
    private const string OPERATION = 'mfa.add_factor';

    /** @var string The address an enrolment's codes go to. */
    private const string DESTINATION = 'ada@example.test';

    /**
     * MFA's route gate asks the freshness gate plainly.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasRouteGateAsksTheFreshnessGatePlainly(): void
    {
        $session  = $this->signIn($this->createPerson())->record;
        $recorder = $this->recordReadModes();

        $this->actingOnVerifiedSession($session)->getJson(self::FRESH_ROUTE)->assertOk()->assertExactJson(['reached' => true]);

        self::assertAskedOnlyIn($recorder, false);
        self::assertAskedOnlyBy($recorder, FreshnessGateAdapter::class, self::OPERATION);
    }

    /**
     * `Mfa::isFresh()` asks the freshness gate plainly.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasFreshnessQuestionAsksTheFreshnessGatePlainly(): void
    {
        $session  = $this->signIn($this->createPerson())->record;
        $recorder = $this->recordReadModes();

        $this->actingOnVerifiedSession($session);

        self::assertTrue(Mfa::isFresh(self::servedCaller(), self::OPERATION));
        self::assertAskedOnlyIn($recorder, false);
        self::assertAskedOnlyBy($recorder, FreshnessGateAdapter::class, self::OPERATION);
    }

    /**
     * MFA's own factor-change gate asks the freshness gate current.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasOwnFactorChangeGateAsksTheFreshnessGateCurrent(): void
    {
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        $this->actingOnVerifiedSession($session);
        $this->bindMfasOwnFactorChangeGate();

        $enrolment = $this->recordReadModes();
        $start     = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp(self::DESTINATION));

        self::assertTrue($start->hasStarted(), $start->reason->value ?? '');
        self::assertAskedOnlyIn($enrolment, true);
        self::assertAskedOnlyBy($enrolment, FreshnessGateAdapter::class, FactorChange::ADD_FACTOR->value);

        $removal = $this->recordReadModes();
        $removed = Mfa::removeFactor(self::servedCaller(), self::onlyFactorOf($person)->id);

        self::assertTrue($removed->wasMade(), $removed->reason->value ?? '');
        self::assertAskedOnlyIn($removal, true);
        self::assertAskedOnlyBy($removal, FreshnessGateAdapter::class, FactorChange::REMOVE_FACTOR->value);
    }

    /**
     * MFA's own factor-change gate asks the reauthenticator current.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasOwnFactorChangeGateAsksTheReauthenticatorCurrent(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $reauthenticated = $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($reauthenticated->isIssued(), $reauthenticated->reason->value ?? '');

        $this->bindMfasOwnFactorChangeGate();

        $recorder = $this->recordReadModes();
        $start    = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp(self::DESTINATION));

        self::assertTrue($start->hasStarted(), $start->reason->value ?? '');
        self::assertAskedOnlyIn($recorder, true);
        self::assertAskedOnlyBy($recorder, ReauthenticatorAdapter::class, Operations::FIRST_ADDITIONAL_FACTOR);
    }

    /**
     * Define the route MFA's gate guards for the operation's freshness.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get(self::FRESH_ROUTE, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa:operation=' . self::OPERATION]);
    }

    /**
     * Bind MFA's own factor-change gate back in place of this package's.
     *
     * @return void
     */
    private function bindMfasOwnFactorChangeGate(): void
    {
        $this->app?->bind(FactorChangeGate::class, ConfiguredFactorChangeGate::class);

        self::assertInstanceOf(ConfiguredFactorChangeGate::class, $this->app?->make(FactorChangeGate::class));
    }

    /**
     * The one confirmed factor the person holds.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private static function onlyFactorOf(Person $person): Factor
    {
        $factors = Factor::query()->where('authenticatable_id', (string) $person->id)->where('status', 'confirmed')->get()->all();

        self::assertCount(1, $factors);
        self::assertInstanceOf(Factor::class, $factors[0]);

        return $factors[0];
    }
}
