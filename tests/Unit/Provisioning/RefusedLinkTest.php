<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Provisioning\RefusedLink;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;

/**
 * Unit tests for the refusal the provisioning listener rolls its transaction
 * back with (IAM-7.1): it carries the helper's answer, and names its status
 * alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusedLink::class)]
final class RefusedLinkTest extends TestCase
{
    /**
     * The refusal carries the helper's answer and names its status.
     *
     * @return void
     */
    public function testTheRefusalCarriesTheAnswerAndNamesItsStatus(): void
    {
        $answer  = ProvisioningResult::expired();
        $refusal = new RefusedLink($answer);

        self::assertSame($answer, $refusal->refusal);
        self::assertSame('SSO\'s provisioning helper refused the link: [expired].', $refusal->getMessage());
    }
}
