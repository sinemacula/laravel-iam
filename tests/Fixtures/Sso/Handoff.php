<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

/**
 * A handoff code SSO issued, with the verifier the client kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Handoff
{
    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @param  string  $reference
     */
    public function __construct(

        /** The handoff code. */
        public string $code,

        /** The verifier the client kept. */
        public string $verifier,

        /** The public reference of the flow's authorisation request. */
        public string $reference,
    ) {}
}
