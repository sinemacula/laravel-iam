<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Provisioning;

use Illuminate\Database\Eloquent\Model;

/**
 * The event of its own a person's model announces its insertion with, built by
 * Eloquent around the model inserted, which it keeps to itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PersonAnnounced
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $person
     */
    public function __construct(

        /** The person inserted. */
        private Model $person,
    ) {}

    /**
     * The person inserted.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function person(): Model
    {
        return $this->person;
    }
}
