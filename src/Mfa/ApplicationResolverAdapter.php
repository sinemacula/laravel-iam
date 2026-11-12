<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;

/**
 * MFA's application is the guard of the same name, the default guard unless MFA
 * names one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationResolverAdapter implements GuardApplicationResolver
{
    /**
     * The default guard's name.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        return $this->resolveForGuard($request, Auth::getDefaultDriver());
    }

    /**
     * The guard's name.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function resolveForGuard(Request $request, string $guard): string
    {
        if (trim($guard) === '') {
            throw UnresolvedReferenceException::forGuard($guard);
        }

        return $guard;
    }
}
