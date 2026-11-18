<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\FactorChanges\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
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
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionTransitionAdapter;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Models\Person;

/**
 * Arranges sessions for the factor-change adapters, bound alone.
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
     * Step the session up with a further factor, failing the test unless it is.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $factor
     * @param  bool  $multifactor
     * @return void
     *
     * @throws \Throwable
     */
    protected function stepUpWith(Person $person, EloquentSession&Model $session, string $factor, bool $multifactor = true): void
    {
        $result = $this->stepUp($person, $session, $factor, $multifactor);

        self::assertTrue($result->isIssued(), sprintf('The session was not stepped up: [%s].', $result->reason->value ?? 'none'));
    }

    /**
     * Step the session up with a multifactor TOTP proof of the factor given, or
     * an email code that is not multifactor.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $factor
     * @param  bool  $multifactor
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    protected function stepUp(Person $person, EloquentSession&Model $session, string $factor, bool $multifactor = true): AccessTokenResult
    {
        return $this->sessions()->stepUp(new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            $multifactor ? 'totp' : 'email',
            new Channel($multifactor ? ChannelKind::AUTHENTICATOR_APP : ChannelKind::EMAIL, $factor),
            $factor,
            new ObservedProperties(userPresence: true),
            new Evaluation(true, $multifactor),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($person, self::GUARD, $session->getSessionIdentifier(), Purpose::STEP_UP),
        ), self::client());
    }

    /**
     * Step the acting session up through MFA with the factor's current code.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     *
     * @throws \Throwable
     */
    protected function stepUpThroughMfa(Factor $factor): void
    {
        $result = Mfa::verify(self::servedCaller(), Submission::factor($factor->id, AuthenticatorApp::code($factor)), MfaPurpose::STEP_UP);

        self::assertTrue($result->isVerified(), (string) $result->reason?->value);
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
     * Store a confirmed TOTP factor of the person's on the application.
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
     * A summary of a confirmed TOTP factor.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    protected static function factorSummary(string $id = 'factor-changed'): FactorSummary
    {
        return new FactorSummary($id, 'totp', 'Phone', null, FactorStatus::CONFIRMED, false, null);
    }

    /**
     * Name the session's key as the person's current sign-in in MFA.
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
     * Ask every session for phishing resistance, which no TOTP step-up shows,
     * so a rejudged one goes pending.
     *
     * @return void
     */
    protected function requirePhishingResistance(): void
    {
        $this->app?->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Ask for phishing resistance of any age.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(phishingResistance: new RequirementPart);
            }
        });
    }

    /**
     * Bind the factor-change adapters while the other adapters stay off.
     *
     * @return void
     */
    protected function bindTheFactorChangeAdapters(): void
    {
        $this->bindTheRequirementCheck();

        $this->app?->bind(FactorChangeGate::class, FactorChangeGateAdapter::class);
        $this->app?->bind(SessionRevoker::class, SessionRevokerAdapter::class);
        $this->app?->bind(SessionTransition::class, SessionTransitionAdapter::class);
    }

    /**
     * Bind the requirement check a factor change's requirement is judged by.
     *
     * @return void
     */
    protected function bindTheRequirementCheck(): void
    {
        $this->app?->bind(RequirementCheck::class, RequirementCheckAdapter::class);
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
