<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Provisioning;

use Illuminate\Database\Eloquent\Model;

/**
 * A person whose model announces its own insertion with an event of its own
 * (`PersonAnnounced`), as an application's identity model may declare in
 * `$dispatchesEvents`, kept in the people's table on the default connection.
 *
 * @property int $id
 * @property string $name
 * @property string $email
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AnnouncedPerson extends Model
{
    /** @var ?string The table people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email'];

    /** @var array<string, class-string> The model's own events: its insertion, announced. */
    protected $dispatchesEvents = ['created' => PersonAnnounced::class];
}
