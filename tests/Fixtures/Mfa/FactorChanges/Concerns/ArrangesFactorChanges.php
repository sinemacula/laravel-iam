<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\FactorChanges\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionTransitionAdapter;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Models\Person;

/**
 * Arranges the sessions the factor-change adapters judge (IAM-3.6 to IAM-3.8):
 * a step-up or a reauthentication made through `laravel-authentication`'s
 * public session service, a factor stored for MFA, MFA's current sign-in named
 * by the session's key, `laravel-authentication` asking for a further factor
 * from now on, and the factor-change adapters bound alone, over the members'
 * defaults, while the rest of this package's adapters are switched off.
 *
 * It is used with `SignsInPeople` and `MigratesMembers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ArrangesFactorChanges
{
    /**
     * Step the session up with a further factor, as MFA's step-up adapter would
     * hand it over once verified, failing the test unless it is.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $factor
     * @return void
     *
     * @throws \Throwable
     */
    protected function stepUpWith(Person $person, EloquentSession&Model $session, string $factor): void
    {
        $result = $this->stepUp($person, $session, $factor);

        self::assertTrue($result->isIssued(), sprintf('The session was not stepped up: [%s].', $result->reason->value ?? 'none'));
    }

    /**
     * Step the session up with a further factor, as MFA's step-up adapter would
     * hand it over once verified: a TOTP code of the factor given, reported
     * multifactor, made now.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $factor
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    protected function stepUp(Person $person, EloquentSession&Model $session, string $factor): AccessTokenResult
    {
        return $this->sessions()->stepUp(new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP, $factor),
            $factor,
            new ObservedProperties(userPresence: true),
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($person, self::GUARD, $session->getSessionIdentifier(), Purpose::STEP_UP),
        ), self::client());
    }

    /**
     * Reauthenticate the session with the person's password, its first factor.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \Throwable
     */
    protected function reauthenticate(Person $person, EloquentSession&Model $session): void
    {
        $result = $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($result->isIssued(), sprintf('The session was not reauthenticated: [%s].', $result->reason->value ?? 'none'));
    }

    /**
     * Store a confirmed TOTP factor of the person's on the application, as an
     * enrolment confirmed in MFA leaves it.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function confirmedFactor(Person $person): Factor
    {
        return Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => ProofOwner::of($person)->key,
            'label'                => 'Phone',
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => CarbonImmutable::now(),
        ]);
    }

    /**
     * A summary of a confirmed TOTP factor, as MFA hands one to a session
     * transition.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    protected static function factorSummary(string $id = 'factor-changed'): FactorSummary
    {
        return new FactorSummary($id, 'totp', 'Phone', null, FactorStatus::CONFIRMED, false, null);
    }

    /**
     * Make MFA's proof store, its own default here, name the session's key as
     * the person's current sign-in, as this package's proof store does, so the
     * sign-in MFA hands the adapters is the guard's session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     */
    protected function nameTheSignIn(Person $person, EloquentSession&Model $session): void
    {
        $this->app?->make(ProofStore::class)->begin($person, self::GUARD, $this->signInReference($session));
    }

    /**
     * From now on, have `laravel-authentication` ask every session for a
     * further factor, which its default requirement check never finds met, so a
     * session judged again returns to pending.
     *
     * @return void
     */
    protected function requireAFurtherFactor(): void
    {
        $this->app?->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Ask for a further factor of any age.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(additionalVerification: new RequirementPart);
            }
        });
    }

    /**
     * Bind the factor-change adapters over MFA's defaults, as this package's
     * binding rule does, while its other adapters stay switched off.
     *
     * @return void
     */
    protected function bindTheFactorChangeAdapters(): void
    {
        $this->app?->bind(FactorChangeGate::class, FactorChangeGateAdapter::class);
        $this->app?->bind(SessionRevoker::class, SessionRevokerAdapter::class);
        $this->app?->bind(SessionTransition::class, SessionTransitionAdapter::class);
    }

    /**
     * The storage connection MFA's transactions, and so the adapters', run on.
     *
     * @return \Illuminate\Database\Connection
     */
    protected static function storage(): Connection
    {
        $connection = DB::connection(StorageConnection::name());

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
