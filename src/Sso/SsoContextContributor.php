<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;

/**
 * The `sso` namespace of `laravel-authentication`'s authentication context,
 * projected from the provenance SSO captured when the session was established
 * (IAM-4.8, SSO-9.7, SSO-9.10, AUTH-11.8).
 *
 * A sign-in this package redeems hands `laravel-authentication` SSO's captured
 * provenance in its stored form as the provider context
 * (`ExternalResults::from()`), which `laravel-authentication` keeps with the
 * session, never rewritten. The contributor reads it back from the contribution
 * subject's provenance (`ContributionSubject::provenance()`, read on the write
 * connection), projects it through SSO's own projection
 * (`Sessions\AuthenticationContext::fromStored()`), and answers each key
 * without its `sso.` prefix, its value as the projection answers it: a string,
 * a list of strings or `null`, the three instants already in
 * `Provenance::INSTANT_FORMAT`. `laravel-authentication`'s own provenance
 * fields are never read: they are the narrower record, and the projection is
 * never rebuilt from them.
 *
 * Absent and null differ. A session with no stored form (one no external
 * provider established, one that is no Eloquent session, or a binding with no
 * session at all) contributes no key, so `has('sso.connection')` is false. A
 * session with one contributes all twelve keys, `null` where the sign-in did
 * not state the fact. A re-authentication records no provider context, so it
 * never changes the keys.
 *
 * Failures propagate, never read as an empty contribution:
 * `laravel-authentication`'s provenance that cannot be read
 * (`InvalidArgumentException`), a stored form this version of SSO did not write
 * (`UnexpectedValueException`), and a database error. A provider context
 * `laravel-authentication` itself cannot read back is its own to read as none.
 *
 * It is registered under `sso` (`AuthenticationContext::NAMESPACE`) in this
 * package's service provider's `boot()`, while the capability's switch is on,
 * and resolved from the container serving each build. It never asks for the
 * authentication context itself, which is being built, and keeps nothing
 * between builds (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoContextContributor implements AuthenticationContextContributor
{
    /**
     * The session's `sso` keys, without their prefix; none for a session SSO
     * did not establish.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, list<string>|string|null>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function contribute(ContributionSubject $subject): array
    {
        $stored = $subject->provenance()?->providerContext?->toArray();
        $prefix = strlen(AuthenticationContext::NAMESPACE) + 1;
        $keys   = [];

        foreach (AuthenticationContext::fromStored($stored) as $key => $value) {
            $keys[substr($key, $prefix)] = $value;
        }

        return $keys;
    }
}
