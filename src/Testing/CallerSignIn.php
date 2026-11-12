<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\ExternalResults;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * Signs a test caller in through the members' real sign-in paths: started, with
 * credentials, or through an admitted SSO redemption.
 *
 * Each sign-in runs in one cross-member transaction and throws a
 * `LogicException` inside it when it does not activate the identity, so nothing
 * it wrote is kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerSignIn
{
    /** @var string The issuer of an SSO caller's provider. */
    public const string ISSUER = 'https://provider.iam.test';

    /** @var string The caller's address (TEST-NET-1, RFC 5737). */
    public const string CLIENT_IP = '192.0.2.1';

    /** @var string The caller's user agent. */
    public const string CLIENT_AGENT = 'laravel-iam-testing';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Testing\CallerCompletion  $completion
     */
    public function __construct(

        /** Resolves the request's admitted redemption record. */
        private Container $container,

        /** Finds the guard's session service. */
        private CurrentSession $sessions,

        /** Runs each sign-in on the storage connection. */
        private CrossMemberTransaction $transaction,

        /** Names the identity as SSO names a link's. */
        private IdentityReferences $identities,

        /** Completes a pending further factor. */
        private CallerCompletion $completion,
    ) {}

    /**
     * Sign the identity in on the guard, completing any pending further factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $tenant
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $verified
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function signIn(
        Identity $identity,
        ?Principal $principal,
        ?string $tenant,
        string $guard,
        CallerSession $session,
        ?AssuranceLevel $verified = null,
    ): EloquentSession&Model {
        $context = new SignInContext(self::client(), principal: $principal, tenant: $tenant === null ? null : TenantSelection::of($tenant));

        return $this->transaction->run(function () use ($identity, $guard, $session, $verified, $context): EloquentSession&Model {
            $result = $this->completed($this->attempt($identity, $guard, $session, $context), $guard, $session, $verified, $context->client);

            return $this->signedIn($result, $identity, $guard, $session);
        });
    }

    /**
     * Refuse scopes, an unclassified level, or a level MFA cannot judge.
     *
     * @param  \SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $verified
     * @param  ?list<string>  $scopes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertActable(CallerSession $session, ?AssuranceLevel $verified, ?array $scopes): void
    {
        if ($scopes !== null) {
            throw new \InvalidArgumentException('Scopes limit only a machine identity; a person acts on a session, which its sign-in limits.');
        }

        if ($verified === null) {
            return;
        }

        VerifiedSession::assertClassified($verified);

        if (!$session->provesFirstFactor()) {
            throw new \InvalidArgumentException('A level needs a first factor MFA can judge: sign the caller in with CallerSession::signedIn() or throughSso().');
        }
    }

    /**
     * Refuse a session or level for a machine, which signs in to no session.
     *
     * @param  ?\SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $verified
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertMachineActable(?CallerSession $session, ?AssuranceLevel $verified): void
    {
        if ($session !== null || $verified !== null) {
            throw new \InvalidArgumentException('A machine identity signs in to no session, so it is acted as with no session and no MFA level.');
        }
    }

    /**
     * The client every test caller signs in from.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public static function client(): ClientContext
    {
        return new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT);
    }

    /**
     * Why the sign-in failed, or what it still waits on.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return string
     */
    public static function reason(SignInResult $result): string
    {
        $waits = array_map(static fn (PendingRequirement $requirement): string => $requirement->value, $result->pending->requires ?? []);

        return $result->reason->value ?? sprintf('%s: %s', $result->status->value, implode(', ', $waits));
    }

    /**
     * The activated session, refusing a failed sign-in or another identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Iam\Testing\CallerSession  $caller
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \LogicException
     */
    private function signedIn(SignInResult $result, Identity $identity, string $guard, CallerSession $caller): EloquentSession&Model
    {
        $refusal = sprintf('The caller did not sign in on guard [%s]: [%s].%s', $guard, self::reason($result), self::hint($result, $caller));
        $session = $result->session ?? throw new \LogicException($refusal);

        if (!$this->identities->reference($session->identity)->is($this->identities->reference($identity))) {
            throw new \LogicException(sprintf('The credentials signed in another identity on guard [%s] than the caller.', $guard));
        }

        return $session->record;
    }

    /**
     * Complete a pending further factor when MFA can judge the first factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $verified
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    private function completed(SignInResult $result, string $guard, CallerSession $session, ?AssuranceLevel $verified, ClientContext $client): SignInResult
    {
        return $session->provesFirstFactor() ? $this->completion->complete($result, $guard, $verified, $client) : $result;
    }

    /**
     * What to do instead when a started session waits on a further factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  \SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @return string
     */
    private static function hint(SignInResult $result, CallerSession $session): string
    {
        $waits = in_array(PendingRequirement::MFA, $result->pending->requires ?? [], true);

        return $waits && !$session->provesFirstFactor()
            ? ' A started session holds no first factor MFA can judge, so the further factor the application requires of a person who holds one cannot complete it:'
                . ' sign the caller in with CallerSession::signedIn() or throughSso().'
            : '';
    }

    /**
     * Sign the identity in on the guard as the session says.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    private function attempt(Identity $identity, string $guard, CallerSession $session, SignInContext $context): SignInResult
    {
        $credentials = $session->credentials();
        $factor      = new FirstFactor($identity, new Channel(ChannelKind::UNKNOWN));

        return match (true) {
            $session->provenance !== null => $this->throughSso($identity, $guard, $session->provenance, $context),
            $credentials         !== null => $this->sessions->sessions($guard)->signIn($session->method, $credentials, $context),
            default                       => $this->sessions->sessions($guard)->start($factor, null, $session->method, $context),
        };
    }

    /**
     * Sign in through an admitted redemption, forgetting it afterwards.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    private function throughSso(Identity $identity, string $guard, Provenance $provenance, SignInContext $context): SignInResult
    {
        $sessions   = $this->sessions->sessions($guard);
        $redemption = $this->redemption($identity, $guard, $provenance);
        $admitted   = $this->container->make(AdmittedRedemptions::class);

        $admitted->record($redemption, ClientTranslator::toSso($context->client));

        try {
            return $sessions->signInExternally(ExternalResults::from($redemption), $context);
        } finally {
            $admitted->forget();
        }
    }

    /**
     * The redemption SSO would admit for the identity and provenance.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    private function redemption(Identity $identity, string $guard, Provenance $provenance): RedemptionResult
    {
        $linkId    = self::linkOf($provenance);
        $reference = $this->identities->reference($identity);
        $result    = new VerifiedResult(
            issuer: self::ISSUER,
            subject: $reference->id,
            nameIdFormat: null,
            connectionId: $provenance->connectionId,
            tenantId: $provenance->tenantId,
            protocol: $provenance->protocol,
            application: $guard,
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::generate(),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext($provenance->providerAuthenticatedAt ?? CarbonImmutable::now()->startOfSecond()),
        );

        return RedemptionResult::redeemed(
            result: $result,
            linkedIdentity: $reference,
            enforcementVersion: $provenance->enforcementVersion,
            sessionNotAfter: $provenance->sessionNotAfter,
            linkId: $linkId,
            admitted: true,
            provenance: $provenance,
        );
    }

    /**
     * The provenance's link; SSO sessions here are always made through a link.
     *
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function linkOf(Provenance $provenance): string
    {
        return $provenance->linkId ?? throw new \InvalidArgumentException('Under laravel-iam an SSO session is established through a link: name the link the provenance admitted.');
    }
}
