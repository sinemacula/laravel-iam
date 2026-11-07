<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Models\Person;

/**
 * Signs people in through an SSO connection and one of their links, as SSO's
 * admitted redemption hands the sign-in to `laravel-authentication`: the
 * redemption is recorded for this request (`AdmittedRedemptions`), and
 * `laravel-authentication`'s external sign-in asks this package's link contract
 * for it, so each session records the connection and the link it was
 * established through, as an SSO sign-in's does.
 *
 * The guard allows the `external_provider` method beside the password, so a
 * test using this overrides nothing else; the record is forgotten once the
 * sign-in returns, as a redemption forgets it. The tables come from
 * `MigratesMembers`, and the people from `SignsInPeople`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait SignsInThroughLinks
{
    /** @var string The connection people sign in through, unless a test names another. */
    protected const string SSO_CONNECTION = 'connection-1';

    /** @var string The tenant every connection belongs to. */
    protected const string SSO_TENANT = 'tenant-1';

    /** @var string The issuer every connection's provider asserts. */
    protected const string ISSUER = 'https://idp.example.test';

    /** @var string The link people sign in through, unless a test names another. */
    protected const string LINK = 'link-1';

    /** @var string The public reference of the authorisation request every result answers. */
    protected const string REQUEST_REFERENCE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    /**
     * Sign the person in on the guard through the connection and the link, and
     * return the session, failing the test unless it starts active.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $connectionId
     * @param  string  $linkId
     * @param  string  $guard
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    protected function signInThrough(Person $person, string $connectionId = self::SSO_CONNECTION, string $linkId = self::LINK, string $guard = self::GUARD): EloquentSession&Model
    {
        $records = $this->admit($person, $connectionId, $linkId);

        try {
            $result = $this->sessions($guard)->signInExternally(self::externalResult($person, $connectionId, $linkId), new SignInContext(self::client()));
        } finally {
            $records->forget();
        }

        if (!$result->isSignedIn() || $result->session === null) {
            self::fail(sprintf('The person did not sign in through the link: [%s].', $result->reason->value ?? $result->status->value));
        }

        return $result->session->record;
    }

    /**
     * Record, for this request, the redemption SSO would admit for the person
     * through the connection and the link, and return the record.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Iam\Sso\AdmittedRedemptions
     */
    protected function admit(Person $person, string $connectionId = self::SSO_CONNECTION, string $linkId = self::LINK): AdmittedRedemptions
    {
        $records = $this->app?->make(AdmittedRedemptions::class);

        self::assertInstanceOf(AdmittedRedemptions::class, $records);

        $records->record(RedemptionResult::redeemed(
            result: self::verified($person, $connectionId),
            linkedIdentity: self::referenceOf($person),
            linkId: $linkId,
            admitted: true,
        ), new SsoClientContext(null, null));

        return $records;
    }

    /**
     * The reference SSO names the person by.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    protected static function referenceOf(Person $person): IdentityReference
    {
        return (new IdentityReferences)->reference($person);
    }

    /**
     * The key the model is named by, as SSO and `laravel-authentication` are
     * handed it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    protected static function keyOf(Model $model): string
    {
        $key = $model->getKey();

        return is_string($key) || is_int($key) ? (string) $key : self::fail('The model has no key.');
    }

    /**
     * The subject the provider asserts of the person.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     */
    protected static function subjectOf(Person $person): string
    {
        return 'subject-' . self::keyOf($person);
    }

    /**
     * The result SSO verified for the person through the connection.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    protected static function verified(Person $person, string $connectionId = self::SSO_CONNECTION): VerifiedResult
    {
        return new VerifiedResult(
            self::ISSUER,
            self::subjectOf($person),
            null,
            $connectionId,
            self::SSO_TENANT,
            'oidc',
            self::GUARD,
            Purpose::SIGN_IN,
            RequestReference::fromString(self::REQUEST_REFERENCE),
            [],
            false,
            new AuthenticationContext(CarbonImmutable::now()->startOfSecond()),
        );
    }

    /**
     * The result `laravel-authentication` is handed for the person through the
     * connection and the link, as built from SSO's redemption.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     */
    protected static function externalResult(Person $person, string $connectionId = self::SSO_CONNECTION, string $linkId = self::LINK): ExternalResult
    {
        return new ExternalResult($connectionId, self::ISSUER, self::subjectOf($person), self::SSO_TENANT, CarbonImmutable::now(), linkId: $linkId);
    }

    /**
     * Allow the `external_provider` method beside the password on the guard.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'external_provider'];
    }
}
