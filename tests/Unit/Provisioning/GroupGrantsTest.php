<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;
use SineMacula\Laravel\Iam\Provisioning\GroupGrants;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Sso\PlainIdentity;

/**
 * Unit tests for writing the grants a person's provider groups give.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GroupGrants::class)]
final class GroupGrantsTest extends TestCase
{
    /**
     * Rows of `[attributes, groups]`.
     *
     * @return iterable<string, array{0: array<string, list<string>|string>, 1: list<string>}>
     */
    public static function provideGroups(): iterable
    {
        yield 'a list' => [['groups' => ['finance', 'finance-ops']], ['finance', 'finance-ops']];

        yield 'a single group' => [['groups' => 'finance'], ['finance']];

        yield 'none' => [['email' => 'ada@example.test'], []];
    }

    /**
     * The groups are read as the provider sent them.
     *
     * @param  array<string, list<string>|string>  $attributes
     * @param  list<string>  $groups
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideGroups')]
    public function testTheGroupsAreReadAsAList(array $attributes, array $groups): void
    {
        self::assertSame($groups, GroupGrants::groupsOf(self::verifiedResult($attributes)));
    }

    /**
     * An identity that is not a model is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsNoModelIsRefused(): void
    {
        $container = new Container;
        $grants    = new GroupGrants($container, new TenantTranslator(new TenantReferences($container)));

        $this->expectException(UnresolvedReferenceException::class);

        $grants->grant(new PlainIdentity(['id' => 1]), 'tenant-1', [GrantInstruction::role('invoices.viewer')]);
    }

    /**
     * A verified result carrying the attributes given.
     *
     * @param  array<string, list<string>|string>  $attributes
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \Random\RandomException
     */
    private static function verifiedResult(array $attributes): VerifiedResult
    {
        return new VerifiedResult(
            'https://idp.example.test',
            'subject-1',
            null,
            'connection-1',
            'tenant-1',
            'oidc',
            'api',
            Purpose::SIGN_IN,
            RequestReference::generate(),
            $attributes,
            false,
            new AuthenticationContext,
        );
    }
}
