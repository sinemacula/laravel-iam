<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Audit\References;
use Tests\Fixtures\Models\Person;

/**
 * Unit tests for the references the mappers name people and tenants by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(References::class)]
final class ReferencesTest extends TestCase
{
    /**
     * Forget any morph map a test set.
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
     * With no morph map, a class name is kept, and the id as a string.
     *
     * @return void
     */
    public function testWithNoMorphMapTheClassNameIsKept(): void
    {
        self::assertSame(['type' => Person::class, 'id' => '7'], References::of(Person::class, '7')?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], References::of(Person::class, 7)?->toArray());
    }

    /**
     * A mapped class is named by its alias, and any other type is kept as it
     * is.
     *
     * @return void
     */
    public function testTheMorphMapNamesAMappedClassByItsAlias(): void
    {
        Relation::morphMap(['person' => Person::class]);

        self::assertSame('person', References::of(Person::class, '7')?->type);
        self::assertSame('person', References::of('person', '7')?->type);
        self::assertSame('application_user', References::of('application_user', '7')?->type);
        self::assertSame('person', References::type(Person::class));
    }

    /**
     * Rows of `[type, id]` with a part missing or empty.
     *
     * @return iterable<string, array{0: ?string, 1: int|string|null}>
     */
    public static function provideMissingParts(): iterable
    {
        yield 'no type' => [null, '7'];

        yield 'an empty type' => ['', '7'];

        yield 'no id' => [Person::class, null];

        yield 'an empty id' => [Person::class, ''];
    }

    /**
     * A missing or empty part is no reference.
     *
     * @param  ?string  $type
     * @param  int|string|null  $id
     * @return void
     */
    #[DataProvider('provideMissingParts')]
    public function testAMissingPartIsNoReference(?string $type, int|string|null $id): void
    {
        self::assertNull(References::of($type, $id));
    }

    /**
     * A tenant is its opaque identifier under the one type, whatever the morph
     * map holds.
     *
     * @return void
     */
    public function testATenantIsItsOpaqueIdentifier(): void
    {
        Relation::morphMap(['tenant' => Person::class]);

        self::assertSame(['type' => 'tenant', 'id' => 'Tenant-007'], References::tenant('Tenant-007')?->toArray());
        self::assertSame(['type' => 'tenant', 'id' => '9'], References::tenant(9)?->toArray());
        self::assertSame('tenant', References::TENANT_TYPE);
        self::assertNull(References::tenant(null));
        self::assertNull(References::tenant(''));
    }

    /**
     * A reference too long to record is refused, never cut into another.
     *
     * @return void
     */
    public function testAReferenceTooLongToRecordIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        References::of(Person::class, str_repeat('7', 192));
    }
}
