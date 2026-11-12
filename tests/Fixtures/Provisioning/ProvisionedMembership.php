<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Provisioning;

use Illuminate\Database\Eloquent\Model;

/**
 * A provisioned person's membership of a tenant.
 *
 * @property int $id
 * @property int $person_id
 * @property string $tenant_id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProvisionedMembership extends Model
{
    /** @var ?string The table memberships are kept in. */
    protected $table = 'iam_provisioned_memberships';

    /** @var list<string> The attributes the provisioner fills. */
    protected $fillable = ['person_id', 'tenant_id'];
}
