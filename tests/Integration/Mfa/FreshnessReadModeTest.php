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
 * How each adapter that judges freshness asks `laravel-authentication`'s
 * freshness policy from every place MFA asks it, with every adapter bound by
 * this package's binding rule, as an application gets them (IAM-3.5):
 *
 * - MFA's route gate and `Mfa::isFresh()` ask the freshness gate outside any
 *   transaction, where nothing acts on the answer atomically: plainly, which
 *   the policy answers there;
 * - MFA's own factor-change gate, which an application may bind back in place
 *   of this package's, asks the freshness gate and the reauthenticator inside
 *   MFA's transaction, after its locks, and grants the change on the answer:
 *   current, which the policy answers there.
 *
 * Neither path meets the `LogicException` the policy throws for a current
 * judgement outside a transaction. The policy is `laravel-authentication`'s
 * own, decorated only to record the read mode each judgement was asked in, the
 * operation it was asked for and the adapter that asked it. Each case checks
 * the adapter: `laravel-authentication`'s own factor-change gate, behind this
 * package's, asks the same policy current too, so a judgement asked on that
 * path never passes for one MFA's own gate asked through an adapter.
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
     * MFA's route gate asks the freshness gate for the operation it names
     * outside any transaction, so the gate asks the policy plainly, and lets a
     * session stepped up just now through.
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
     * `Mfa::isFresh()` asks the freshness gate outside any transaction, so the
     * gate asks the policy plainly.
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

        self::assertTrue(Mfa::isFresh(self::OPERATION));
        self::assertAskedOnlyIn($recorder, false);
        self::assertAskedOnlyBy($recorder, FreshnessGateAdapter::class, self::OPERATION);
    }

    /**
     * MFA's own factor-change gate, bound back by the application, asks the
     * freshness gate inside MFA's transaction, after its locks, for adding a
     * further factor (until when, the enrolment's grant) and for removing one
     * (whether), so the gate asks the policy current, for MFA's operation of
     * each change, and both changes are made.
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
        $start     = Mfa::startEnrollment(EnrollmentRequest::totp(self::DESTINATION));

        self::assertTrue($start->hasStarted(), $start->reason->value ?? '');
        self::assertAskedOnlyIn($enrolment, true);
        self::assertAskedOnlyBy($enrolment, FreshnessGateAdapter::class, FactorChange::ADD_FACTOR->value);

        $removal = $this->recordReadModes();
        $removed = Mfa::removeFactor(self::onlyFactorOf($person)->id);

        self::assertTrue($removed->wasMade(), $removed->reason->value ?? '');
        self::assertAskedOnlyIn($removal, true);
        self::assertAskedOnlyBy($removal, FreshnessGateAdapter::class, FactorChange::REMOVE_FACTOR->value);
    }

    /**
     * MFA's own factor-change gate, bound back by the application, asks the
     * reauthenticator inside MFA's transaction, after its locks, for a first
     * additional factor, so the reauthenticator asks the policy current, for
     * the operation a reauthentication authorises, and the enrolment starts on
     * a reauthentication made just now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasOwnFactorChangeGateAsksTheReauthenticatorCurrent(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $reauthenticated = $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD]);

        self::assertTrue($reauthenticated->isIssued(), $reauthenticated->reason->value ?? '');

        $this->bindMfasOwnFactorChangeGate();

        $recorder = $this->recordReadModes();
        $start    = Mfa::startEnrollment(EnrollmentRequest::totp(self::DESTINATION));

        self::assertTrue($start->hasStarted(), $start->reason->value ?? '');
        self::assertAskedOnlyIn($recorder, true);
        self::assertAskedOnlyBy($recorder, ReauthenticatorAdapter::class, Operations::FIRST_ADDITIONAL_FACTOR);
    }

    /**
     * Define the route MFA's gate guards for the operation's freshness, on the
     * stateless guard.
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
     * Bind MFA's own factor-change gate back in place of this package's, as an
     * application may once every provider has registered, so MFA asks the
     * freshness gate and the reauthenticator itself, failing unless MFA then
     * resolves its own gate.
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
