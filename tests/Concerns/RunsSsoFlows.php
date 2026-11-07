<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\EveryoneMayLink;
use Tests\Fixtures\Sso\Handoff;

/**
 * Runs SSO's flows end to end against a fake OpenID provider, with no network,
 * through SSO's public services alone, so a redemption test redeems a handoff
 * code SSO issued itself, as an application's redemption endpoint does.
 *
 * `arrangeSso()` configures SSO for the guard people sign in on (the SSO
 * application of the same name, allowing sign-in through an external provider),
 * answers SSO's outbound requests with the fake provider, and creates and
 * enables an OIDC connection of the tenant trusting it. It binds stand-ins only
 * for freshness (`FakeFreshness`, fresh), which judges a caller this package is
 * handed, and link eligibility (`EveryoneMayLink`), which this package answers
 * from the application's memberships only once they are configured; without
 * either, SSO refuses every `link`. A test of link eligibility itself forgets
 * the stand-in. Every other seam is the one the package binds. A flow is
 * started (`handoff()`) and answered at the provider, which completes it and
 * hands back the code and verifier the client presents. A SAML connection of
 * the same tenant, trusting a fake SAML identity provider, is made on demand
 * (`makeSamlConnection()`), and its flows run the same way (`samlHandoff()`):
 * the provider's response carries an eight-hour `SessionNotOnOrAfter`, which
 * SSO's default deadline contract lets limit the session, so a SAML sign-in is
 * the one whose redemption carries a session deadline.
 *
 * The guard allows `external_provider` alongside the password, which every test
 * that signs someone in through SSO needs. It is used with `SignsInPeople` and
 * `MigratesSso`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RunsSsoFlows
{
    /** @var string The tenant every connection belongs to. */
    protected const string TENANT = 'tenant-1';

    /** @var string Where the application's handoff goes. */
    protected const string REDIRECT_URI = 'https://app.iam.test/sso';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    protected ?FakeOpenIdProvider $provider = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeFetcher What answers SSO's outbound requests. */
    protected ?FakeFetcher $fetcher = null;

    /** @var string The connection that trusts the provider. */
    protected string $connectionId = '';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The tenant's SAML identity provider, once a SAML connection is made. */
    protected ?FakeSamlIdentityProvider $idp = null;

    /**
     * The sign-in methods the guard allows: the password, and sign-in through
     * an external provider.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'external_provider'];
    }

    /**
     * Configure SSO for the guard, bind the stand-ins and the fake provider,
     * and create and enable the tenant's OIDC connection.
     *
     * @return void
     */
    protected function arrangeSso(): void
    {
        $this->fetcher  = new FakeFetcher;
        $this->provider = new FakeOpenIdProvider;

        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new EveryoneMayLink);

        Config::set('sso.features.oidc', true);
        Config::set('sso.endpoints.base_url', 'https://sp.iam.test');
        Config::set('sso.applications', [self::GUARD => ['redirect_uri' => self::REDIRECT_URI, 'external_sign_in' => true]]);

        $this->connectionId = $this->makeConnection();
    }

    /**
     * Create and enable an OIDC connection of the tenant given, the tests' own
     * unless another is named, trusting the provider, and answer its id.
     *
     * @param  string  $tenant
     * @return string
     */
    protected function makeConnection(string $tenant = self::TENANT): string
    {
        $provider    = $this->provider                             ?? self::fail('SSO is not arranged.');
        $connections = $this->app?->make(ConnectionService::class) ?? self::fail('The application has not booted.');

        $provider->serve($this->fetcher ?? self::fail('SSO is not arranged.'));

        $created = $connections->create($tenant, 'oidc', 'Example OIDC', self::ssoClient(), [
            'issuer'                 => $provider->issuer,
            'authorization_endpoint' => $provider->endpoint('authorization'),
            'token_endpoint'         => $provider->endpoint('token'),
            'jwks_uri'               => $provider->endpoint('jwks'),
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            'client_secret'          => FakeOpenIdProvider::CLIENT_SECRET,
        ]);

        $connectionId = (string) $created->connection?->id;

        self::assertTrue($connections->enable($tenant, $connectionId, self::ssoClient())->isSucceeded());

        return $connectionId;
    }

    /**
     * Start a flow of the purpose for the identity and session given, have the
     * provider answer it, complete it at the connection's callback, and answer
     * the handoff code the client is sent back with and the verifier it kept.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Tests\Fixtures\Models\Person  $identity
     * @param  ?string  $sessionId
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @return \Tests\Fixtures\Sso\Handoff
     *
     * @throws \Random\RandomException
     */
    protected function handoff(Purpose $purpose = Purpose::SIGN_IN, ?Person $identity = null, ?string $sessionId = null, ?\Closure $tailor = null): Handoff
    {
        $app      = $this->app      ?? self::fail('The application has not booted.');
        $provider = $this->provider ?? self::fail('SSO is not arranged.');
        $start    = $this->started($purpose, $this->connectionId, $identity, $sessionId);
        $grant    = $provider->authorize($start, $tailor);
        $request  = new CompletionRequest('GET', $grant->query(), []);
        $result   = $app->make(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connectionId, $request, self::ssoClient());

        return self::handedOff($app->make(CompletionResponses::class)->from($result, 'GET'), $start);
    }

    /**
     * Create and enable a SAML connection of the tenant trusting a new fake
     * SAML identity provider's certificate, and answer its id.
     *
     * @return string
     */
    protected function makeSamlConnection(): string
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        Config::set('sso.features.saml2', true);

        $this->idp = new FakeSamlIdentityProvider;

        $connections = $app->make(ConnectionService::class);
        $created     = $connections->create(self::TENANT, 'saml2', 'Example SAML', self::ssoClient(), [
            'idp_entity_id' => $this->idp->entityId,
            'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
        ]);

        $connectionId = (string) $created->connection?->id;

        self::assertTrue($app->make(KeyService::class)->trustCertificate(self::TENANT, $connectionId, $this->idp->certificate(), self::ssoClient())->isSucceeded());
        self::assertTrue($connections->enable(self::TENANT, $connectionId, self::ssoClient())->isSucceeded());

        return $connectionId;
    }

    /**
     * Start a flow of the purpose through the SAML connection, for the identity
     * given, have the SAML identity provider answer the request the start sent
     * now, post its response to the assertion consumer service, and answer the
     * handoff code the client is sent back with and the verifier it kept.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Tests\Fixtures\Models\Person  $identity
     * @return \Tests\Fixtures\Sso\Handoff
     *
     * @throws \Random\RandomException
     * @throws \DOMException
     */
    protected function samlHandoff(string $connectionId, Purpose $purpose = Purpose::SIGN_IN, ?Person $identity = null): Handoff
    {
        $app      = $this->app ?? self::fail('The application has not booted.');
        $idp      = $this->idp ?? self::fail('No SAML connection is made.');
        $start    = $this->started($purpose, $connectionId, $identity, null);
        $request  = $idp->receive($start);
        $response = $idp->respondTo($request, CarbonImmutable::now());
        $posted   = $response->completionRequest($request->relayState);
        $result   = $app->make(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $connectionId, $posted, self::ssoClient());

        return self::handedOff($app->make(CompletionResponses::class)->from($result, 'POST'), $start);
    }

    /**
     * Link the person to the provider's subject through a whole `link` flow,
     * redeemed by this package's link redemption as the person.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    protected function linkThroughFlow(Person $person): RedemptionResult
    {
        $handoff = $this->handoff(Purpose::LINK, $person);
        $linked  = Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $person);

        self::assertTrue($linked->isRedeemed(), sprintf('The person was not linked: [%s].', $linked->reason->value ?? $linked->status->value));

        return $linked;
    }

    /**
     * The key the session is named by, as SSO is handed it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return string
     */
    protected static function keyOf(Model $session): string
    {
        $key = $session->getKey();

        return is_string($key) || is_int($key) ? (string) $key : self::fail('The session has no key.');
    }

    /**
     * The reference SSO names the person by.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    protected static function referenceOf(Person $person): IdentityReference
    {
        return new IdentityReference($person->getMorphClass(), (string) $person->getKey());
    }

    /**
     * The tests' client, as SSO is handed it.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    protected static function ssoClient(): SsoClientContext
    {
        return new SsoClientContext(self::CLIENT_IP, self::CLIENT_AGENT);
    }

    /**
     * Start a flow of the purpose through the connection for the identity and
     * session given, failing unless it starts.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @param  ?\Tests\Fixtures\Models\Person  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Random\RandomException
     */
    private function started(Purpose $purpose, string $connectionId, ?Person $identity, ?string $sessionId): StartResult
    {
        $app   = $this->app ?? self::fail('The application has not booted.');
        $start = $app->make(AuthorizationRequestService::class)->start(
            self::GUARD,
            $purpose,
            $connectionId,
            self::ssoClient(),
            null,
            $identity === null ? null : self::referenceOf($identity),
            $sessionId,
        );

        self::assertTrue($start->isStarted(), sprintf('The flow did not start: [%s].', $start->reason->value ?? $start->status->value));

        return $start;
    }

    /**
     * The handoff code the completion's response sends the client back with,
     * with the verifier the client kept from the start, failing unless the flow
     * completed with one.
     *
     * @param  \SineMacula\Laravel\Sso\Responses\CompletionResponse  $response
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \Tests\Fixtures\Sso\Handoff
     */
    private static function handedOff(CompletionResponse $response, StartResult $start): Handoff
    {
        $redirect = HandoffRedirect::from($response);

        self::assertTrue($redirect->hasCode(), sprintf('The flow did not complete: [%s].', $redirect->error ?? 'no code'));

        return new Handoff($redirect->code(), $start->verifier?->reveal() ?? self::fail('The client holds no verifier.'), (string) $start->reference?->value);
    }
}
