<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\AuditCheck;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for the audit trail's checks (IAM-9, IAM-2.5): the mappers
 * registered while they are on; every `jwt` and `api_key` guard excluded from
 * audit-log's own capture, its Gate capture off, its refusal of unregistered
 * codes on whatever they say (decision Q5 (a)).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditCheck::class)]
final class AuditCheckTest extends TestCase
{
    use RunsChecks;

    /** @var string Why the guard the tests sign in on is refused while audit-log still captures it. */
    private const string UNEXCLUDED = 'Guards [api] are missing from `audit-log.capture.laravel.except_guards`, '
        . 'so each of their sign-ins is recorded twice: add them.';

    /** @var string Why audit-log's Gate capture on is refused. */
    private const string GATE_CAPTURE_ON = '`audit-log.capture.gate.enabled` must be false, so no authorization decision is recorded twice:'
        . ' this package maps laravel-authorization\'s decision events, the Gate checks laravel-authorization answers among them.';

    /** @var string Why audit-log recording unregistered codes is refused. */
    private const string UNREGISTERED = '`audit-log.definitions.require_registered` must be true, '
        . 'so a code without a definition is refused rather than recorded unchecked; turn it on.';

    /**
     * Audit-log as it ships, with the mappers on, records the guard's sign-ins
     * twice and codes unchecked, and both are refused.
     *
     * @return void
     */
    public function testAuditLogAsItShipsFails(): void
    {
        self::assertSame([self::UNEXCLUDED, self::UNREGISTERED], self::problems($this->check()->checks()));
        self::assertTrue($this->check()->applies());
        self::assertSame('audit', $this->check()->subject());
    }

    /**
     * The audit-log values the application owes pass.
     *
     * @return void
     */
    public function testTheOwedValuesPass(): void
    {
        $this->setOwedValues();

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Audit-log's Gate capture on is refused.
     *
     * @return void
     */
    public function testGateCaptureOnFails(): void
    {
        $this->setOwedValues();

        $this->app?->make('config')->set(CaptureExclusions::GATE_KEY, true);

        self::assertSame([self::GATE_CAPTURE_ON], self::problems($this->check()->checks()));
    }

    /**
     * An exclusion list that is no list of guard names is refused, naming the
     * key and never the value.
     *
     * @return void
     */
    public function testAMalformedExclusionListFails(): void
    {
        $this->setOwedValues();

        $this->app?->make('config')->set(CaptureExclusions::EXCEPT_GUARDS_KEY, 'api');

        self::assertSame(['`audit-log.capture.laravel.except_guards` must be a list of guard names, or [\'*\'].'], self::problems($this->check()->checks()));
    }

    /**
     * Mappers that never registered with audit-log are refused.
     *
     * @return void
     */
    public function testMappersThatNeverRegisteredFail(): void
    {
        $this->setOwedValues();

        $this->app?->offsetUnset(AuditRegistrations::REGISTERED);

        $problem = 'The audit mappers are not registered with laravel-audit-log; '
            . 'register laravel-iam\'s provider before the application boots, or turn `iam.audit.mappers` off.';

        self::assertSame([$problem], self::problems($this->check()->checks()));
    }

    /**
     * Rows of values the mappers' switch reads as off from.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function mappersOff(): iterable
    {
        yield 'false' => [false];
        yield 'zero' => ['0'];
        yield 'off' => ['off'];
        yield 'no' => ['no'];
    }

    /**
     * With the mappers off, audit-log is still held to IAM-2.5 (decision Q5
     * (a)): every guard excluded, Gate capture off and unregistered codes
     * refused; only the mappers' registration is no longer required.
     *
     * @param  mixed  $off
     * @return void
     */
    #[DataProvider('mappersOff')]
    public function testWithTheMappersOffAuditLogsValuesAreStillEnforced(mixed $off): void
    {
        $config = $this->app?->make('config');

        $config?->set(AuditSettings::MAPPERS, $off);
        $config?->set(CaptureExclusions::GATE_KEY, true);
        $config?->set(AuditSettings::REQUIRE_REGISTERED, false);

        $this->app?->offsetUnset(AuditRegistrations::REGISTERED);

        self::assertSame([self::UNEXCLUDED, self::GATE_CAPTURE_ON, self::UNREGISTERED], self::problems($this->check()->checks()));

        $this->setOwedValues();
        $config?->set(CaptureExclusions::GATE_KEY, false);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Set the audit-log values the application owes.
     *
     * @return void
     */
    private function setOwedValues(): void
    {
        $config = $this->app?->make('config');

        $config?->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['api']);
        $config?->set(AuditSettings::REQUIRE_REGISTERED, true);
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\AuditCheck
     */
    private function check(): AuditCheck
    {
        $check = $this->app?->make(AuditCheck::class);

        assert($check instanceof AuditCheck);

        return $check;
    }
}
