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
 * Signs a caller in for `Concerns\InteractsWithIam::actingAsCaller()`, as the
 * application signs people in, so the session it acts on is a live, active
 * session `laravel-authentication` wrote, holding its first factor and the
 * principal and the active tenant the sign-in chose, and, through SSO, the
 * provenance a redemption records.
 *
 * A session `CallerSession::started()` is started through
 * `laravel-authentication`'s `start()`, as an application starts one for an
 * identity it verified itself; one `CallerSession::signedIn()` is signed in
 * through `signIn()` with the credentials, which must sign in the very identity
 * acted as. One `CallerSession::throughSso()` is signed in as `Iam::signIns()`
 * signs a person in once SSO admitted a redemption: the redemption is recorded
 * for the request (`AdmittedRedemptions`), with the identity as the link's and
 * the provenance as SSO's, and `signInExternally()` is handed the external
 * result built from it, so the link contract finds the identity and the session
 * records the connection, the link and the provenance as its provider context,
 * which the `sso` context namespace reads back. The provider's issuer is
 * `ISSUER` and its subject names the identity's key; neither is kept beyond the
 * sign-in, and the record is forgotten once the sign-in returns, whether it
 * signed in or not.
 *
 * Every sign-in comes from the client `client()` names, runs in this package's
 * cross-member transaction on the storage connection, and must activate the
 * very identity acted as. A sign-in left pending on a further factor, as a
 * person who already holds a confirmed factor is left under an application that
 * then requires one, is completed in that transaction (`CallerCompletion`) when
 * the session holds a first factor MFA can judge (signed in with credentials or
 * through SSO). A refusal, a sign-in still pending (on a choice of principal,
 * or a started session on a further factor), or one that signed in another
 * identity, throws a `LogicException` naming the guard and the reason (for a
 * started session, what to do instead) inside that transaction, so whatever the
 * sign-in wrote is rolled back with it and a test never acts on, or leaves
 * behind, a session it did not mean to.
 *
 * Stateless: the guard's session service and the request's record are resolved
 * on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerSignIn
{
    /** @var string The issuer the provider of an SSO caller's sign-in asserts. */
    public const string ISSUER = 'https://provider.iam.test';

    /** @var string The address a caller signs in from (TEST-NET-1, RFC 5737). */
    public const string CLIENT_IP = '192.0.2.1';

    /** @var string The user agent a caller signs in with. */
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

        /** Resolves the request's record of the admitted redemption on each call. */
        private Container $container,

        /** Finds the session service of the guard. */
        private CurrentSession $sessions,

        /** Runs each sign-in in one transaction on the storage connection. */
        private CrossMemberTransaction $transaction,

        /** Names the identity as SSO names a link's identity. */
        private IdentityReferences $identities,

        /** Completes a sign-in left pending on a further factor. */
        private CallerCompletion $completion,
    ) {}

    /**
     * Sign the identity in on the guard, as the principal given (or its
     * default), in the tenant given (or the principal's default), as the
     * session says, completing a sign-in left pending on a further factor with
     * a proof of the level's evidence (AAL2's when none is given), and return
     * the session.
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
     * Refuse, before anything is signed in, what a person cannot act with:
     * scopes, which limit only a machine; the unclassified level, which no
     * proof supports; and a level for a session whose first factor MFA cannot
     * judge, after which MFA accepts no further proof.
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
     * Refuse, before anything is acted on, what a machine cannot act with: a
     * session or a level, since a machine signs in to no session.
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
     * The client every caller signs in from, `VerifiedSignInRecorderAdapter`'s
     * included.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public static function client(): ClientContext
    {
        return new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT);
    }

    /**
     * Why the sign-in did not sign in: the reason it failed, or, left pending,
     * what it still waits on.
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
     * The session the sign-in activated for the identity, refusing a sign-in
     * that did not activate and one that signed in another identity.
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
     * The sign-in, completed when it waits first on a further factor and the
     * session holds a first factor MFA can judge, after which alone MFA accepts
     * one.
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
     * What to do instead when a session started with no first factor MFA can
     * judge waits on a further factor, which MFA accepts after none; nothing
     * otherwise.
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
     * Sign the identity in on the guard as SSO's admitted redemption with the
     * provenance would, and forget the redemption once the sign-in returns.
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
     * The redemption SSO would admit for the identity through the provenance's
     * connection and link, on the guard.
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
     * The link the provenance admitted, refusing provenance that names none:
     * under this package an SSO session is always established through a link.
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
