<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The callers handed to this package in this request for SSO's freshness
 * contract to judge, each with the application it is judged on (IAM-4.6,
 * SSO-2.12): the caller of a `link` redemption running, or the caller the
 * application hands in around its own call into SSO (`CallerScope::run()`).
 *
 * SSO hands its freshness contract only the operation and its maximum age,
 * never the caller or the application, and the adapter never takes either from
 * the request or the default guard. `LinkRedemption` is handed both as plain
 * values, as `CallerScope` is, so each opens the record with them before SSO is
 * asked (`open()`) and closes it once SSO has answered or thrown (`close()`),
 * and the freshness adapter judges the caller's own session on that
 * application's guard (`current()`), never a session of whoever else the guard
 * serves. With none open, nothing is judged, and the answer is `stale`.
 *
 * Each entry also records whether a transaction was already open on the storage
 * connection when the caller was handed in. A plain read inside a transaction
 * opened before then may answer from a snapshot older than the call (MySQL's
 * `REPEATABLE READ`), still counting a proof voided or a session revoked since,
 * and the session's row cannot be locked where SSO asks without inverting SSO's
 * lock order, so the freshness adapter answers `stale` for such a caller while
 * that transaction is open.
 *
 * The record keeps one entry per caller open, the latest answering, so a
 * redemption run while another is still open in the same container (as a test
 * runs a racing request) leaves the other's in place; a close with none open
 * changes nothing. It is bound scoped, under this package's own key for scoped
 * adapters, so it holds one request's or one job's callers alone, and the
 * worker reset forgets it (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LinkCallers
{
    /** @var list<array{application: string, caller: \SineMacula\Laravel\Sso\Identities\IdentityReference, inTransaction: bool}> The callers open, the latest last. */
    private array $open = [];

    /**
     * Open the record for the caller, on the application, noting whether a
     * transaction was already open on the storage connection when the caller
     * was handed in.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  bool  $inTransaction
     * @return void
     */
    public function open(string $application, IdentityReference $caller, bool $inTransaction): void
    {
        $this->open[] = ['application' => $application, 'caller' => $caller, 'inTransaction' => $inTransaction];
    }

    /**
     * Close the record of the latest caller open, if any.
     *
     * @return void
     */
    public function close(): void
    {
        array_pop($this->open);
    }

    /**
     * The latest caller open, with its application and whether a transaction
     * was already open when it was handed in, or `null` when none is open.
     *
     * @return ?array{application: string, caller: \SineMacula\Laravel\Sso\Identities\IdentityReference, inTransaction: bool}
     */
    public function current(): ?array
    {
        return $this->open === [] ? null : $this->open[array_key_last($this->open)];
    }
}
