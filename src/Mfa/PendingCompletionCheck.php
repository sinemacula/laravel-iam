<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use SineMacula\Laravel\Iam\Exceptions\CookieTransportUnsupportedException;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;

/**
 * Refuses an application whose pending sign-ins this package's pending
 * completion could never complete: one that has it bound while a session
 * guard's refresh token travels in a cookie.
 *
 * `laravel-authentication`'s `satisfy()` judges a cookie application's
 * same-site facts (the `Origin` presented, the request's own scheme and host,
 * the CSRF header) before it reads the pending session, and refuses a client
 * that carries none as `cross_site_request`. MFA hands its pending completion
 * the pending context alone, never the caller's client, and MFA's client keeps
 * no same-site facts in any case, so the completion hands `satisfy()` a client
 * of which nothing is known (`PendingCompletionAdapter`): on a cookie guard it
 * could never activate a pending session, whatever request the person proved
 * their further factor in. It never reads a request to pass the check instead,
 * and never invents same-site facts nobody judged. Until the members hand the
 * completion a judged client, the application is refused when it boots, naming
 * the guard, rather than refusing each person when they sign in.
 *
 * Only this package's own completion is judged: an application that binds its
 * own, or turns the MFA capability off, is left alone, as is one whose session
 * guards all carry the refresh token in the body. What the container will build
 * for the seam is read from its binding table, without building it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingCompletionCheck
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\MemberDefaults  $bindings
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Reads what the container will build for the seam. */
        private MemberDefaults $bindings,

        /** Names the guards that hold sessions. */
        private CurrentSession $sessions,
    ) {}

    /**
     * Refuse the application when this package's pending completion is bound
     * and a session guard's refresh token travels in a cookie.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\CookieTransportUnsupportedException
     */
    public function assertCompletable(Container $container, Repository $config): void
    {
        if (!$this->bindings->isBoundTo($container, PendingCompletion::class, [PendingCompletionAdapter::class])) {
            return;
        }

        foreach ($this->sessions->sessionGuards() as $guard) {

            if (RefreshTokenTransport::forGuard($guard, $config)->usesCookie()) {
                throw CookieTransportUnsupportedException::forPendingCompletion($guard);
            }
        }
    }
}
