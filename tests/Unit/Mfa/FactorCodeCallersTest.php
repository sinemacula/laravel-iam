<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa;

use Illuminate\Auth\GenericUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCallers;
use SineMacula\Laravel\Mfa\Context\CallerContext;

/**
 * Unit tests for the callers kept beside MFA's factor code bindings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorCodeCallers::class)]
final class FactorCodeCallersTest extends TestCase
{
    /**
     * The caller kept for a binding is read back for that binding.
     *
     * @return void
     */
    public function testTheCallerKeptForABindingIsReadBack(): void
    {
        $callers = new FactorCodeCallers;
        $binding = self::binding();
        $caller  = CallerContext::nobody('api');

        self::assertSame($binding, $callers->hold($binding, $caller));
        self::assertSame($caller, $callers->of($binding));
    }

    /**
     * A binding nothing was kept for has no caller.
     *
     * @return void
     */
    public function testAnotherBindingHasNoCaller(): void
    {
        $callers = new FactorCodeCallers;

        $callers->hold(self::binding(), CallerContext::nobody('api'));

        self::assertNull($callers->of(self::binding()));
    }

    /**
     * A caller kept again for the same binding replaces the one kept before.
     *
     * @return void
     */
    public function testACallerKeptAgainReplacesTheLastOne(): void
    {
        $callers = new FactorCodeCallers;
        $binding = self::binding();
        $caller  = CallerContext::nobody('admin');

        $callers->hold($binding, CallerContext::nobody('api'));
        $callers->hold($binding, $caller);

        self::assertSame($caller, $callers->of($binding));
    }

    /**
     * A factor code binding of the same factor, sign-in and channel each time.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    private static function binding(): FactorCodeBinding
    {
        $identity = new class (['id' => 7]) extends GenericUser implements Identity {};

        return new FactorCodeBinding(new ProofBinding($identity, 'api', 'session-1', Purpose::STEP_UP), 'factor-1', new Channel(ChannelKind::SMS, '+447700900123'));
    }
}
