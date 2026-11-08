<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Callers\Caller;

/**
 * The callers handed to this package in this request for SSO's freshness
 * contract to judge (IAM-4.6, SSO-2.12): the caller of a `link` redemption
 * running, or the caller the application hands in around its own call into SSO
 * (`CallerScope::run()`).
 *
 * SSO hands its freshness contract only the operation and its maximum age,
 * never the caller, and the adapter never takes one from the request, the
 * default guard or the session a guard serves. `LinkRedemption` and
 * `CallerScope` are each handed the caller as a plain value,
 * `laravel-authentication`'s `Caller` (its guard, its identity and the session
 * its credential holds, as `Auth::caller()` reads them where the application
 * reads the request), so each opens the record with it before SSO is asked
 * (`open()`) and closes it once SSO has answered or thrown (`close()`), and the
 * freshness adapter judges that caller's own session alone (`current()`). With
 * none open, nothing is judged, and the answer is `stale`.
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
    /** @var list<array{caller: \SineMacula\Laravel\Authentication\Callers\Caller, inTransaction: bool}> The callers open, the latest last. */
    private array $open = [];

    /**
     * Open the record for the caller, noting whether a transaction was already
     * open on the storage connection when the caller was handed in.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @param  bool  $inTransaction
     * @return void
     */
    public function open(Caller $caller, bool $inTransaction): void
    {
        $this->open[] = ['caller' => $caller, 'inTransaction' => $inTransaction];
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
     * The latest caller open, with whether a transaction was already open when
     * it was handed in, or `null` when none is open.
     *
     * @return ?array{caller: \SineMacula\Laravel\Authentication\Callers\Caller, inTransaction: bool}
     */
    public function current(): ?array
    {
        return $this->open === [] ? null : $this->open[array_key_last($this->open)];
    }
}
