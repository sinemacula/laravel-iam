<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A session policy source answering as the source it wraps does, recording each
 * answer, so a test can tell which scopes `laravel-authorization`'s checks were
 * capped by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSessionPolicySource implements SessionPolicySource
{
    /** @var list<list<string>|null> The answers given, in order. */
    public array $answers = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SessionPolicySource  $source
     */
    public function __construct(

        /** The source whose answers are recorded. */
        private readonly SessionPolicySource $source,
    ) {}

    /**
     * Answer as the wrapped source does, and record the answer.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        $answer = $this->source->scopesFor($subject);

        $this->answers[] = $answer;

        return $answer;
    }
}
