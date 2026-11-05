<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings\Contracts;

/**
 * A seam no member binds, unless a test adds the member that binds it with a
 * plain `bind()` of a class name, as laravel-mfa bound its defaults before
 * laravel-mfa#92 and laravel-authorization still binds its resolvers
 * (IAM-13.7).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface PlainSeam {}
