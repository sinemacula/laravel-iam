<?php

declare(strict_types = 1);

namespace Tests\Unit\Bindings;

use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use Tests\Fixtures\Bindings\Adapter;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\MemberDefault;

/**
 * Unit tests for declaring one member seam this package binds an adapter over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamBinding::class)]
final class SeamBindingTest extends TestCase
{
    /**
     * Declared with only its seam, adapter and defaults, a binding is
     * transient, always on, not mandatory, and asks its member nothing.
     *
     * @return void
     */
    public function testABindingIsTransientAlwaysOnAndOptionalByDefault(): void
    {
        $binding = new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class]);

        self::assertSame(PlainSeam::class, $binding->abstract);
        self::assertSame(Adapter::class, $binding->adapter);
        self::assertSame([MemberDefault::class], $binding->memberDefaults);
        self::assertSame(Lifetime::TRANSIENT, $binding->lifetime);
        self::assertNull($binding->appliesWhen);
        self::assertFalse($binding->mandatory);
        self::assertFalse($binding->isMandatory());
        self::assertNull($binding->holdsDefault);
        self::assertNull($binding->factory);
        self::assertNull($binding->declare);
    }

    /**
     * A binding keeps the lifetime, switch, mandatory flag, member's answer and
     * declaration it is declared with.
     *
     * @return void
     */
    public function testABindingKeepsWhatItIsDeclaredWith(): void
    {
        $switch       = static fn (Repository $config): bool => $config->has('iam');
        $holdsDefault = static fn (): bool => true;
        $declare      = static function (): void {};
        $binding      = new SeamBinding(PlainSeam::class, Adapter::class, [], Lifetime::SCOPED, $switch, true, holdsDefault: $holdsDefault, declare: $declare);

        self::assertSame([], $binding->memberDefaults);
        self::assertSame(Lifetime::SCOPED, $binding->lifetime);
        self::assertSame($switch, $binding->appliesWhen);
        self::assertTrue($binding->mandatory);
        self::assertTrue($binding->isMandatory());
        self::assertSame($holdsDefault, $binding->holdsDefault);
        self::assertSame($declare, $binding->declare);
    }

    /**
     * A binding over a member's contract asks that member whether it holds its
     * default, unless it is declared with an answer of its own.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testABindingOverAMembersContractAsksTheMember(): void
    {
        $asked        = new SeamBinding(TenantResolver::class, Adapter::class, []);
        $holdsDefault = static fn (): bool => true;
        $answer       = new \ReflectionFunction($asked->holdsDefault ?? self::fail('The member is not asked.'));

        self::assertSame(AuthenticationServiceProvider::class, $answer->getClosureScopeClass()?->getName());
        self::assertSame($holdsDefault, (new SeamBinding(TenantResolver::class, Adapter::class, [], holdsDefault: $holdsDefault))->holdsDefault);
    }

    /**
     * A mandate declared as a closure is asked each time it is read, and never
     * before.
     *
     * @return void
     */
    public function testAMandateDeclaredAsAClosureIsAskedWhenItIsRead(): void
    {
        $answers = new \ArrayObject([true, false]);
        $asked   = new \ArrayObject;
        $binding = new SeamBinding(PlainSeam::class, Adapter::class, [], mandatory: static function () use ($answers, $asked): bool {

            $asked->append(true);

            return (bool) $answers[count($asked) - 1];
        });

        self::assertCount(0, $asked);
        self::assertTrue($binding->isMandatory());
        self::assertFalse($binding->isMandatory());
        self::assertCount(2, $asked);
    }
}
