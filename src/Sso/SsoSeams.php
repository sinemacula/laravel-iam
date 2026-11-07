<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;

/**
 * The seams `laravel-authentication` and SSO join through (IAM-4.2 to IAM-4.4,
 * IAM-4.9): re-authentication sessions, session revocation, the external
 * identity links and SSO's own link store.
 *
 * - SSO's `ReauthenticationSessions` is answered from
 *   `laravel-authentication`'s external standing, with its renewal recorded for
 *   the redemption's one write (`ReauthenticationSessionsAdapter`).
 * - SSO's `SessionRevocation` ends `laravel-authentication`'s sessions inside
 *   SSO's change (`SessionRevocationAdapter`). It is mandatory: left on SSO's
 *   default, an enforcement change, a disabled or deleted connection, a removed
 *   link or a widened scope would leave every session it concerns standing.
 * - `laravel-authentication`'s `ExternalIdentityLinks` answers from the
 *   redemption SSO admitted in this request alone
 *   (`ExternalIdentityLinksAdapter`).
 * - SSO's `Linker` is SSO's own `Links\LinkStore`, which implements
 *   `LinkStorage` too: links are SSO's, and `laravel-authentication` stores
 *   none. SSO finds its link storage only as the linker bound, so `LinkStorage`
 *   is answered from whatever linker is bound (`BoundLinkStorage`), the store
 *   by default, and never from a store of its own that an application's own
 *   linker would not see. SSO binds no link storage of its own, so that seam is
 *   bound only while unbound. Neither keeps anything of one request for the
 *   next, but each holds the container (the store resolves its link limit and
 *   its reporter from it), so both are scoped, as SSO's own guide binds the
 *   store, and a long-lived worker never reaches one request's container from
 *   another (IAM-8.1).
 *
 * SSO's handoff issuer is never bound: SSO issues and redeems its own handoff
 * codes, so it keeps its default, `Handoffs\DatabaseHandoffStore`.
 *
 * Each adapter replaces the member's own default only; an application's binding
 * is kept (IAM-8.4). The adapters keep nothing and resolve the records this
 * package keeps for a redemption (`AdmittedRedemptions`, `RenewalRecorder`) on
 * every call, so each is transient. The whole capability is switched by
 * `iam.adapters.sso`: off, nothing here binds, and each member keeps its own
 * default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoSeams implements ProvidesSeams
{
    /** @var string The switch that turns every binding here on or off. */
    public const string SWITCH = 'iam.adapters.sso';

    /**
     * Return the bindings between `laravel-authentication` and SSO, each on
     * while the capability's switch is.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on = static fn (Repository $switches): bool => self::isOn($switches);

        return [
            new SeamBinding(ReauthenticationSessions::class, ReauthenticationSessionsAdapter::class, [NoReauthenticationSessions::class], appliesWhen: $on),
            new SeamBinding(SessionRevocation::class, SessionRevocationAdapter::class, [NoSessionRevocation::class], appliesWhen: $on, mandatory: true),
            new SeamBinding(ExternalIdentityLinks::class, ExternalIdentityLinksAdapter::class, [NoExternalLinks::class], appliesWhen: $on),
            new SeamBinding(Linker::class, LinkStore::class, [NoLinks::class], Lifetime::SCOPED, $on),
            new SeamBinding(LinkStorage::class, BoundLinkStorage::class, [], Lifetime::SCOPED, $on),
        ];
    }

    /**
     * Whether the capability's switch leaves its bindings on, read leniently,
     * as the members read a switch an environment variable fills: `false`, as a
     * boolean or as text, `0`, `off` and `no` turn it off; anything else, a
     * missing or empty value included, leaves it on, since the package requires
     * every member and binds them together unless told not to.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isOn(Repository $config): bool
    {
        $value = $config->get(self::SWITCH);

        return $value === null || $value === '' || (filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true);
    }
}
