<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Iam\Delivery\MfaSenderAdapter;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * MFA's challenge gateway, sending and checking a delivered factor's codes
 * through `laravel-authentication`'s factor codes (IAM-3.9), for each factor
 * whose code that path delivers as MFA would, and through MFA's own challenge
 * gateway for every other.
 *
 * `laravel-authentication`'s path takes a factor's code only while
 * `laravel-authentication`'s one-time code sender is bound and the factor is of
 * MFA's own `sms` or `email` type, delivered by MFA's own driver over this
 * package's sender of that channel (the sender the driver holds, not the one
 * the container binds), so the code would reach the same gateway either way.
 * Every other delivered factor's code is sent and checked by MFA's
 * `PackageChallengeGateway`, built from the container on each call, so the
 * driver of its type delivers it inside MFA's transaction, as MFA's contract
 * asks: a driver the application registers through `Mfa::extend()` (an override
 * of `sms` or `email`, MFA's own driver over a sender of the application's
 * among them, or a type of its own, of any channel kind), a driver over a
 * sender the application bound, and every code while no one-time code sender is
 * bound. The choice is made against the container as it stands on each call,
 * never when the providers register, so a driver or a sender the application
 * registers later, in its own provider's `register()` or `boot()`, is the one
 * used, whatever order the providers register in (IAM-8.4), and MFA's boot
 * check judges the senders its codes go through. A factor's sends and checks
 * take the same path, since the choice depends on its type alone.
 *
 * On `laravel-authentication`'s path a send is
 * `Auth::codes($application)->sendFactorCode()` and a check
 * `verifyFactorCode()`, on the guard the binding's application names, under a
 * factor code binding made from MFA's: the factor's owner, the application, the
 * sign-in, the purpose, the factor, its channel (the kind its driver states,
 * naming its destination) and, for an enrolment, the pending factor as the
 * grant (see `Translation\CodeTranslator`). `laravel-authentication` keeps the
 * challenge, its attempts and deliveries and its per-IP limits; it asks MFA's
 * challenge counters, through `FactorCodeCountersAdapter`, before each delivery
 * and each check and once for each attempt it counts, all inside its own
 * transaction on the shared storage connection, a savepoint of MFA's when MFA
 * calls from inside its identity's lock. Its answer is translated into MFA's
 * send result and challenge outcome. `laravel-authentication` answers a used,
 * unknown or malformed challenge as it answers a wrong code, so each fails as
 * MFA's counted `invalid_code`, never `replayed` or `not_found`: never a pass,
 * and never a refusal that would let a wrong code's count roll back.
 *
 * There the code is delivered by `laravel-authentication`'s one-time code
 * sender, from its queued job once the outermost transaction commits, never by
 * MFA's senders: MFA reports it sent once it is issued, and a delivery that
 * fails fails the job, which the queue retries, rather than rolling the code
 * back. `laravel-authentication`'s counts on code requests and checks are taken
 * in MFA's transaction when MFA calls from inside one, so they commit or roll
 * back with it, and MFA's own throttle on the IP address counts the same
 * request too.
 *
 * A factor that keeps no state of its own on a row, or that is not the
 * binding's identity's, is not found, as MFA's own gateway finds none; a
 * reauthentication proves the first factor, so no code is sent or checked for
 * one. An application that names no guard of `laravel-authentication`'s that
 * holds sessions, and a factor owned by an identity `laravel-authentication`
 * does not sign in, cannot be resolved and throw (IAM-8.2). The session the
 * binding names is MFA's counters' to judge, inside the transaction.
 *
 * It holds nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChallengeGatewayAdapter implements ChallengeGateway
{
    /** @var string The detail of a check refused for a factor that is not the binding's identity's. */
    public const string NOT_FOUND = 'The factor is not one of the binding\'s identity\'s stored factors.';

    /** @var string The detail of a check refused for a reauthentication. */
    public const string REAUTHENTICATION = 'A reauthentication proves the first factor, so no factor code answers one.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator  $codes
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves `laravel-authentication`'s code service for the guard. */
        private AuthFactory $auth,

        /** Resolves the guard the application names, and the identity as `laravel-authentication`'s. */
        private CurrentSession $sessions,

        /** Translates the binding, the request and the check. */
        private CodeTranslator $codes,

        /** Tells whether a one-time code sender is bound, and builds MFA's own challenge gateway. */
        private Container $container,
    ) {}

    /**
     * Send a code for the factor, bound as the binding says: through
     * `laravel-authentication`'s factor codes when that path delivers it as MFA
     * would, and through MFA's own challenge gateway otherwise.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function send(Factor $factor, ProofBinding $binding): SendResult
    {
        $kind = $this->routedKind($factor);

        if ($kind === null) {
            return $this->mfasOwn()->send($factor, $binding);
        }

        $codes = $this->service($binding->application);
        $owner = self::owner($factor, $binding);

        return match (true) {
            $owner            === null                    => SendResult::refused(FailureReason::NOT_FOUND),
            $binding->purpose === Purpose::REAUTHENTICATE => SendResult::refused(FailureReason::NOT_ACCEPTED),
            default                                       => $this->codes->sendResult($codes->sendFactorCode($this->bound($owner, $factor, $kind, $binding))),
        };
    }

    /**
     * Check the code against the challenge, bound as the binding says, on the
     * path its code was sent on: `laravel-authentication`'s factor codes, or
     * MFA's own challenge gateway.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function verify(Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        $kind = $this->routedKind($factor);

        if ($kind === null) {
            return $this->mfasOwn()->verify($factor, $binding, $challengeId, $code);
        }

        $codes = $this->service($binding->application);
        $owner = self::owner($factor, $binding);

        return match (true) {
            $owner            === null                    => ChallengeOutcome::refused(FailureReason::NOT_FOUND, self::NOT_FOUND),
            $binding->purpose === Purpose::REAUTHENTICATE => ChallengeOutcome::refused(FailureReason::NOT_ACCEPTED, self::REAUTHENTICATION),
            default                                       => $this->codes->outcome($codes->verifyFactorCode($this->bound($owner, $factor, $kind, $binding), $challengeId, $code)),
        };
    }

    /**
     * The factor's owner, when the factor keeps state of its own on a row and
     * its owner is the identity the binding names.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function owner(Factor $factor, ProofBinding $binding): ?MultiFactorAuthenticatable
    {
        $owner = $factor instanceof EloquentFactor ? $factor->authenticatable()->getResults() : null;

        return $owner instanceof MultiFactorAuthenticatable && IdentityReference::of($owner)->owns($binding) ? $owner : null;
    }

    /**
     * The channel kind the factor's code goes out on through
     * `laravel-authentication`'s factor codes, or `null` when MFA's own
     * challenge gateway sends it: no one-time code sender is bound, or the
     * factor's type is not delivered by MFA's own driver over this package's
     * sender (`isPointedAtGateway()`).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    private function routedKind(Factor $factor): ?ChannelKind
    {
        if (!$this->container->bound(OneTimeCodeSender::class)) {
            return null;
        }

        $type   = $factor->getType();
        $driver = Mfa::driver($type);

        return self::isPointedAtGateway($driver, $type) ? $driver->channelKind() : null;
    }

    /**
     * Whether the driver of the type is MFA's own driver of that type, `sms` or
     * `email`, over this package's sender of its channel: its code reaches the
     * channel's gateway on either path, and `laravel-authentication`'s delivers
     * it as MFA would. The sender judged is the one the driver holds, not the
     * one the container binds, so MFA's own driver the application registers
     * through `Mfa::extend()` over a sender of its own delivers through that
     * sender, as does MFA's own over a sender the application bound. Any other
     * driver, the application's own above all, delivers the code itself.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  string  $type
     * @return bool
     */
    private static function isPointedAtGateway(FactorDriver $driver, string $type): bool
    {
        $isShipped = match (true) {
            $driver instanceof SmsDriver   => $type === ChannelKind::SMS->value,
            $driver instanceof EmailDriver => $type === ChannelKind::EMAIL->value,
            default                        => false,
        };

        return $isShipped && self::senderOf($driver) instanceof MfaSenderAdapter;
    }

    /**
     * Return the sender MFA's own SMS or email driver delivers through: the one
     * it was built with, from the property its own `send()` reads, which
     * neither driver exposes any other way.
     *
     * @param  \SineMacula\Laravel\Mfa\Drivers\EmailDriver|\SineMacula\Laravel\Mfa\Drivers\SmsDriver  $driver
     * @return \SineMacula\Laravel\Mfa\Contracts\EmailSender|\SineMacula\Laravel\Mfa\Contracts\SmsSender
     */
    private static function senderOf(EmailDriver|SmsDriver $driver): EmailSender|SmsSender
    {
        return \Closure::bind(static fn (EmailDriver|SmsDriver $driver): EmailSender|SmsSender => $driver->sender, null, $driver::class)($driver);
    }

    /**
     * MFA's own challenge gateway, built from the container, which sends and
     * checks a code through the driver of the factor's type.
     *
     * @return \SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function mfasOwn(): PackageChallengeGateway
    {
        return $this->container->make(PackageChallengeGateway::class);
    }

    /**
     * The factor code binding the factor's codes are issued and checked under,
     * for its owner as `laravel-authentication`'s identity, on the channel kind
     * its driver states.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $owner
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function bound(MultiFactorAuthenticatable $owner, Factor $factor, ChannelKind $kind, ProofBinding $binding): FactorCodeBinding
    {
        return $this->codes->toAuthentication($this->sessions->identity($owner), $factor, $kind, $binding);
    }

    /**
     * `laravel-authentication`'s code service for the guard the application
     * names, which must be one of its guards that holds sessions.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function service(string $application): CodeService
    {
        $auth = $this->auth;

        if (!$auth instanceof AuthManager) {
            throw UnresolvedReferenceException::forGuard($application);
        }

        $this->sessions->guard($application);

        return $auth->codes($application);
    }
}
