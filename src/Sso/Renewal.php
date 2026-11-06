<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The renewal SSO's redemption of a `reauthenticate` code asked for, as its
 * reauthentication sessions contract was handed it (IAM-4.2): the identity, the
 * session, the time the provider authenticated the identity, and the evidence
 * SSO's evidence contract accepted of it, if any.
 *
 * It is recorded, never written, when SSO asks for it, and the one write is
 * made from it once SSO's admission answers, through `laravel-authentication`'s
 * external re-authentication (`ReauthenticationRedemption`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Renewal
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     */
    public function __construct(

        /** The identity the flow was started for. */
        public IdentityReference $identity,

        /** The session the flow was started on. */
        public string $sessionId,

        /** When the provider authenticated the identity. */
        public CarbonImmutable $authenticatedAt,

        /** What SSO's evidence contract accepted of the result's own assertion; none when it accepted nothing. */
        public ?AcceptedEvidence $evidence,
    ) {}
}
