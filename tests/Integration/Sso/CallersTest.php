<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Sso\Callers;
use SineMacula\Laravel\Sso\Identities\Caller as SsoCaller;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * Integration tests for naming the application's caller as SSO's caller.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Callers::class)]
final class CallersTest extends TestCase
{
    use MigratesSso, RunsSsoFlows, SignsInPeople;

    /**
     * Arrange SSO for the guard.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();
    }

    /**
     * Outside a transaction the caller carries its own session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerOutsideATransactionCarriesItsSession(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $named = Iam::callers()->of($this->requestCallerOf($person));

        self::assertSame(SignIn::reference($session, self::GUARD), $named->sessionId);
    }

    /**
     * Inside a transaction on the storage connection the caller carries none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerInsideATransactionCarriesNoSession(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $caller = $this->requestCallerOf($person);
        $named  = DB::connection(StorageConnection::name())->transaction(static fn (): SsoCaller => Iam::callers()->of($caller));

        self::assertNull($named->sessionId);
    }

    /**
     * A caller holding no access session carries none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerWithoutAnAccessSessionCarriesNoSession(): void
    {
        $person = $this->createPerson();

        $named = Iam::callers()->of(new Caller(self::GUARD, CallerCredential::ACCESS, $person, null, null, null));

        self::assertNull($named->sessionId);
    }
}
