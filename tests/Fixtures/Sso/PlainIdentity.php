<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Auth\GenericUser;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * An identity that is no Eloquent model, so SSO cannot name it by reference.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainIdentity extends GenericUser implements Identity {}
