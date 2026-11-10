<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Iam\Mfa\PasskeyFactorGateAdapter;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RegistersPasskeys;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\RequiresNothing;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests of a passkey factor enrolled while the MFA application
 * offered the `passkey` type, once the application has withdrawn the type and
 * redeployed (IAM-3.10): MFA's passkey gateway is back on MFA's own default, so
 * no ceremony runs, but the passkey factor gate stays bound, so a passkey that
 * is still a factor is never removed leaving its factor and association
 * standing, and a removal MFA refuses rolls back whole. They run on every
 * database, and also at READ COMMITTED and REPEATABLE READ on MySQL and
 * PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyFactorGateAdapter::class)]
#[CoversClass(PasskeySeams::class)]
final class WithdrawnPasskeyFactorsTest extends TestCase
{
    use MigratesMembers, RegistersPasskeys, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The passkey's credential id, in unpadded base64url. */
    private const string CREDENTIAL = 'd2l0aGRyYXduLXBhc3NrZXk';

    /**
     * Removing, through `laravel-authentication`, a passkey that is still an
     * MFA factor once the type is withdrawn takes its factor and association
     * with it in the same change, on a session stepped up with another factor,
     * while MFA's passkey gateway stays on MFA's own default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyFactorLeftByAWithdrawnTypeIsRemovedWithItsPasskey(): void
    {
        self::assertInstanceOf(UnavailablePasskeyGateway::class, $this->resolved(PasskeyGateway::class));
        self::assertInstanceOf(PasskeyFactorGateAdapter::class, $this->resolved(PasskeyFactorGate::class));

        $this->assertTheRemovalTakesTheFactor();
    }

    /**
     * The removal takes the factor and association with it at each isolation
     * level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAPasskeyFactorLeftByAWithdrawnTypeIsRemovedWithItsPasskeyAtEachLevel(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $this->assertTheRemovalTakesTheFactor();
    }

    /**
     * A removal MFA refuses, on a session with no fresh step-up, rolls back
     * whole: the passkey, its factor and its association all stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedRemovalKeepsThePasskeyAndItsFactor(): void
    {
        $this->assertTheRefusedRemovalRollsBack();
    }

    /**
     * A refused removal rolls back whole at each isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefusedRemovalKeepsThePasskeyAndItsFactorAtEachLevel(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $this->assertTheRefusedRemovalRollsBack();
    }

    /**
     * Require no factor of anyone, so the session stays active once it signs
     * in.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->singleton(IdentityRequirement::class, RequiresNothing::class);
        $app->make('config')->set('mfa.applications.' . self::GUARD . '.requirement', 'never');
    }

    /**
     * The application has withdrawn the `passkey` type: it offers TOTP alone.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return ['totp'];
    }

    /**
     * Remove the person's enrolled passkey on a session stepped up with another
     * factor, and assert its factor and association went with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheRemovalTakesTheFactor(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        [$factor, $passkeyId] = $this->enrolledPasskeyFactor($person);

        $this->stepUpWithAnotherFactor($person);

        $removal = $this->passkeys()->remove($person, $passkeyId, self::client());

        self::assertTrue($removal->isRemoved());
        self::assertNotNull($removal->completion, 'MFA removed the factor in the same change.');
        self::assertFalse(Passkey::query()->whereKey($passkeyId)->exists());
        self::assertNull(Factor::query()->find($factor->id), 'No passkey factor is left standing.');
        self::assertSame(0, PasskeyAssociation::query()->count(), 'No association is left standing.');
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * Remove the person's enrolled passkey on a session with no fresh step-up,
     * and assert MFA refused it and nothing was removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheRefusedRemovalRollsBack(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        [$factor, $passkeyId] = $this->enrolledPasskeyFactor($person);

        try {
            $this->passkeys()->remove($person, $passkeyId, self::client());

            self::fail('MFA must refuse a removal without a fresh step-up.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);
        }

        self::assertTrue(Passkey::query()->whereKey($passkeyId)->exists());
        self::assertNotNull(Factor::query()->find($factor->id));
        self::assertSame(1, PasskeyAssociation::query()->count());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * The person's passkey, with the confirmed MFA factor and association it
     * was enrolled as while the type was offered, and the passkey's id.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return array{0: \SineMacula\Laravel\Mfa\Models\Factor, 1: string}
     *
     * @throws \Throwable
     */
    private function enrolledPasskeyFactor(Person $person): array
    {
        $registration = $this->registerPasskey($person, self::CREDENTIAL);

        self::assertTrue($registration->isRegistered(), $registration->status->value);
        self::assertNull($registration->factor, 'With no binding, the passkey is not associated.');
        self::assertNotNull($registration->passkey);

        $owner  = IdentityReference::of($person);
        $factor = Factor::query()->create([
            'type'                 => PasskeySeams::TYPE,
            'credential_reference' => self::CREDENTIAL,
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'label'                => 'Laptop',
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => CarbonImmutable::now(),
        ]);

        $associations = $this->app?->make(PasskeyAssociations::class);

        self::assertInstanceOf(PasskeyAssociations::class, $associations);

        $associations->associate(new ProofOwner($owner->type, $owner->key), $factor->id, self::CREDENTIAL);

        return [$factor, $registration->passkey->id];
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * Give the person an authenticator app factor beside the passkey, and step
     * the session up with it through MFA, as removing a factor asks of a
     * session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpWithAnotherFactor(Person $person): void
    {
        $kept = Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => IdentityReference::of($person)->key,
            'label'                => 'Phone',
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => CarbonImmutable::now(),
        ]);

        $result = Mfa::verify(self::servedCaller(), Submission::factor($kept->id, AuthenticatorApp::code($kept)), Purpose::STEP_UP);

        self::assertTrue($result->isVerified(), (string) $result->reason?->value);
    }
}
