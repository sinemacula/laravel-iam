<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Models\Person;

/**
 * Unit tests for naming an identity as MFA names it on a proof's binding: its
 * morph class for an Eloquent identity and its class name otherwise, with its
 * key as a string, refusing a key that could let two identities meet.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityReference::class)]
final class IdentityReferenceTest extends TestCase
{
    /**
     * Forget the morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * An Eloquent identity is named by its morph class, honouring the
     * application's morph map, and its key as a string.
     *
     * @return void
     */
    public function testAnEloquentIdentityIsNamedByItsMorphClass(): void
    {
        $person = new Person;

        $person->setAttribute('id', 7);

        $reference = IdentityReference::of($person);

        self::assertSame(Person::class, $reference->type);
        self::assertSame('7', $reference->key);

        Relation::morphMap(['person' => Person::class]);

        self::assertSame('person', IdentityReference::of($person)->type);
    }

    /**
     * Any other identity is named by its class name, and a string key is kept
     * as it is.
     *
     * @return void
     */
    public function testAnyOtherIdentityIsNamedByItsClassName(): void
    {
        $reference = IdentityReference::of(new GenericUser(['id' => '01JC0000000000000000000000']));

        self::assertSame(GenericUser::class, $reference->type);
        self::assertSame('01JC0000000000000000000000', $reference->key);
    }

    /**
     * Rows of `[key]` MFA cannot name an identity by.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnsupportedKeys(): iterable
    {
        yield 'none' => [null];

        yield 'empty' => [''];

        yield 'a number with a fraction' => [1.5];

        yield 'a list' => [[7]];
    }

    /**
     * A key that is neither a non-empty string nor an integer is refused, as an
     * identity that cannot be resolved.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('provideUnsupportedKeys')]
    public function testAnUnsupportedKeyIsRefused(mixed $key): void
    {
        try {
            IdentityReference::of(new GenericUser(['id' => $key]));

            self::fail('An identity was named by a key MFA cannot hold.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString(GenericUser::class, $exception->getMessage());
        }
    }

    /**
     * Two references name the same identity only with the same type and key.
     *
     * @return void
     */
    public function testTwoReferencesNameTheSameIdentityOnlyWithTheSameTypeAndKey(): void
    {
        $person = new Person;

        $person->setAttribute('id', 7);

        $reference = IdentityReference::of(new GenericUser(['id' => 7]));

        self::assertTrue($reference->is(IdentityReference::of(new GenericUser(['id' => '7']))));
        self::assertFalse($reference->is(IdentityReference::of(new GenericUser(['id' => 8]))));
        self::assertFalse($reference->is(IdentityReference::of($person)));
    }

    /**
     * A reference owns MFA's proof binding only when the binding names its type
     * and its key.
     *
     * @return void
     */
    public function testAReferenceOwnsABindingOnlyWithTheSameTypeAndKey(): void
    {
        $reference = IdentityReference::of(new GenericUser(['id' => 7]));

        self::assertTrue($reference->owns(new ProofBinding(GenericUser::class, '7', 'api', 'sign-in', Purpose::STEP_UP)));
        self::assertFalse($reference->owns(new ProofBinding(GenericUser::class, '8', 'api', 'sign-in', Purpose::STEP_UP)));
        self::assertFalse($reference->owns(new ProofBinding(Person::class, '7', 'api', 'sign-in', Purpose::STEP_UP)));
    }
}
