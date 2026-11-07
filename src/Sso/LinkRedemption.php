<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Iam\Transactions\OutermostCommits;
use SineMacula\Laravel\Iam\Transactions\RetrySettings;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Redeems a `link` handoff code SSO issued, linking the caller's identity to
 * the provider's subject (IAM-4.3, AUTH-3.9, SSO-8.3).
 *
 * A `link` creates a link and no session, so it is redeemed through SSO's
 * standalone redemption (`HandoffRedemption::redeem()`), with no transaction of
 * this package's: SSO opens its own on its storage connection, takes its locks
 * in its order, asks freshness (`sso.link.create`), the identity's eligibility,
 * the link's continuity and, for an identity holding or having held a verified
 * domain link, link confirmation, then creates or confirms the link and commits
 * before it answers. It restarts itself once when it comes to a verified domain
 * link in a connection it did not lock. The redemption is redeemed but never
 * admitted (`isAdmitted()` is false), and nothing written after it is protected
 * by it. Every refusal is SSO's, and is answered as the result.
 *
 * A standalone redemption whose transaction fails on a concurrency failure
 * (SQLSTATE 40001, a deadlock, a lock wait timeout, or a second
 * `LinkCandidatesChanged`) before it commits has been rolled back whole by SSO,
 * the consumption included, so it is redeemed again from its start, still
 * standalone, up to the attempts the retry helper is configured with
 * (IAM-11.2). On PostgreSQL at REPEATABLE READ, a `link` that waited on another
 * holder of the identity's guard (a second submission of the same callback,
 * another link of the same person's, a reservation's activation, a principal's
 * widening) fails to serialise once the other commits, and the next attempt
 * sees what it committed. Each attempt is counted against the client's IP
 * address, as SSO counts every redemption. An attempt that reached its commit
 * (`OutermostCommits` counted one on the storage connection while it ran) is
 * never run again, whatever it then failed on: the link is written and the code
 * spent, and what failed is the commit itself or what ran after it (SSO
 * dispatches its events from the commit, and a listener's exception propagates
 * from it), so a second attempt would only find the code replayed, report a
 * refusal of a link that was made and spend another attempt. The last attempt's
 * failure, and any other, reaches the caller as the database raised it
 * (`ConcurrencyFailures::asRaised()`), a `QueryException` for the database's,
 * even one met in a transaction SSO nests in its own, and the caller retries
 * the request.
 *
 * Called while the caller holds a transaction open on SSO's storage connection,
 * SSO's `redeem()` is what its `admit()` is instead: the link is written inside
 * the caller's transaction, is admitted, and commits or rolls back with it, not
 * before this method answers. It is run once there, through the cross-member
 * transaction (`CrossMemberTransaction::run()`), in a savepoint of the caller's
 * transaction that is rolled back whenever it fails, so a caller that catches
 * the failure and commits keeps none of SSO's writes (the consumption, the
 * single-use record, the link) on every supported Laravel version, and its
 * failure reaches the caller in a form the caller's own retry recognises
 * (`ConcurrencyFailures::forCaller()`), for the caller to retry its whole
 * transaction. This package refuses neither path: which one runs is SSO's.
 *
 * The caller is the identity the application has authenticated, handed over as
 * a plain value: the identity of the session the request is served with, which
 * the application reads where it reads the request, never from the request's
 * body. It is named to SSO as an Eloquent identity's morph class and its key
 * (`IdentityReferences::reference()`), the reference SSO started the flow for;
 * an identity that is no Eloquent model, or whose key is neither a non-empty
 * string nor an integer, throws `UnresolvedReferenceException` before the code
 * is touched (IAM-8.2). A code started for another identity is SSO's
 * `identity_mismatch`.
 *
 * The application is resolved to its guard before SSO is asked, standalone or
 * inside the caller's transaction, as a sign-in's and a re-authentication's
 * application is: it must be a declared guard of the `jwt` driver
 * (`CurrentSession::guard()`), or an `UnresolvedReferenceException` is thrown
 * before the code is touched (IAM-8.2), and the code stays unspent. A `link`
 * writes no session, so the guard is resolved and never asked anything. A guard
 * the code was not started for is SSO's `application_mismatch`, answered once
 * SSO has consumed the code.
 *
 * It reads no request, nor the guard's current user or session. While SSO
 * redeems the code, the application and the caller are kept in this request's
 * record of callers (`LinkCallers`), which SSO's freshness contract is judged
 * for under SSO's locks (`FreshnessAdapter`), since SSO hands that contract
 * neither. Inside the caller's transaction, that transaction's snapshot may be
 * older than the redemption and the session's row cannot be locked where SSO
 * asks, so the record says so and the freshness adapter answers `stale`: such a
 * `link` is SSO's `freshness_required`, unless the application binds a
 * freshness contract of its own. SSO's redemption, the request's count of
 * outermost commits and the record are resolved on each call. The code and the
 * verifier are handed to the caller's transaction's work wrapped in a
 * `SensitiveParameterValue`, and unwrapped only inside it, so the trace of
 * anything thrown there never holds either in the clear.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class LinkRedemption
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Storage\StorageConnection  $storage
     * @param  \SineMacula\Laravel\Iam\Transactions\RetrySettings  $settings
     * @param  \SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures  $failures
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves SSO's redemption on each call. */
        private Container $container,

        /** Names the caller as SSO names an identity. */
        private IdentityReferences $identities,

        /** The connections the redemption runs on. */
        private DatabaseManager $database,

        /** The storage connection's name. */
        private StorageConnection $storage,

        /** How many times a standalone redemption is attempted. */
        private RetrySettings $settings,

        /** Which failures a standalone redemption is attempted again after. */
        private ConcurrencyFailures $failures,

        /** Runs a redemption inside the caller's transaction in a savepoint of it. */
        private CrossMemberTransaction $transaction,

        /** Resolves the application to the guard it is. */
        private CurrentSession $sessions,
    ) {}

    /**
     * Redeem the `link` code for the application through the connection, with
     * its verifier, for the client, as the caller, and answer SSO's result.
     *
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function redeem(
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        Identity $caller,
    ): RedemptionResult {
        $this->sessions->guard($application);

        $reference  = $this->identities->reference($caller);
        $connection = $this->database->connection($this->storage->name());
        $callers    = $this->container->make(LinkCallers::class);

        $inCallersTransaction = $connection->transactionLevel() > 0;

        $callers->open($application, $reference, $inCallersTransaction);

        try {
            return $inCallersTransaction
                ? $this->inCallersTransaction($application, $connectionId, $code, $verifier, $client, $reference)
                : $this->standalone($connection, $application, $connectionId, $code, $verifier, $client, $reference);
        } finally {
            $callers->close();
        }
    }

    /**
     * Redeem the code once, inside the caller's transaction, in a savepoint of
     * it rolled back whenever the redemption fails, and rethrow its failure as
     * the caller's own retry recognises it.
     *
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function inCallersTransaction(
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        IdentityReference $caller,
    ): RedemptionResult {
        $secrets = new \SensitiveParameterValue([$code, $verifier]);

        return $this->transaction->run(function () use ($application, $connectionId, $secrets, $client, $caller): RedemptionResult {

            [$code, $verifier] = $secrets->getValue();

            return $this->attempt($application, $connectionId, $code, $verifier, $client, $caller);
        });
    }

    /**
     * Redeem the code standalone, again from its start after a concurrency
     * failure SSO rolled back whole before its commit, up to the configured
     * attempts, and rethrow the last attempt's failure, a failure met once the
     * attempt reached its commit, or any other, as the database raised it.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     *
     * @SuppressWarnings("php:S107")
     */
    private function standalone(
        Connection $connection,
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        IdentityReference $caller,
    ): RedemptionResult {
        $attempts = $this->settings->attempts();
        $commits  = $this->container->make(OutermostCommits::class);

        for ($attempt = 1;; $attempt++) {

            $begun = $commits->count($connection);

            try {
                return $this->attempt($application, $connectionId, $code, $verifier, $client, $caller);
            } catch (\Throwable $exception) {

                if ($attempt >= $attempts || $commits->count($connection) !== $begun || !$this->failures->isRetryable($exception)) {
                    throw $this->failures->asRaised($exception);
                }
            }
        }
    }

    /**
     * Ask SSO's redemption, once, to redeem the `link` code as the caller.
     *
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function attempt(
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        IdentityReference $caller,
    ): RedemptionResult {
        return $this->container->make(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            $application,
            $connectionId,
            $code,
            $verifier,
            ClientTranslator::toSso($client),
            $caller,
        );
    }
}
