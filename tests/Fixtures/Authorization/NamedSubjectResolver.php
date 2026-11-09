<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * An application's own subject resolver, which it names in
 * `laravel-authorization`'s configuration (`authorization.subject_resolver`):
 * it resolves no subject, and makes the user handed in its own subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NamedSubjectResolver implements SubjectResolver
{
    /**
     * No subject.
     *
     * @return ?\SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        return null;
    }

    /**
     * The user as its own subject.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return new Subject($user);
    }
}
