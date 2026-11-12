<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseManager;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;

/**
 * Unit tests that a redemption's code and verifier never reach a trace in the
 * clear.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRedemption::class)]
#[CoversClass(ReauthenticationRedemption::class)]
final class RedemptionSecretsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string A code of a handoff's shape. */
    private const string CODE = 'the-handoff-code-the-client-presents-012345';

    /** @var string A verifier of a handoff's shape. */
    private const string VERIFIER = 'the-verifier-the-client-kept-for-its-code-0';

    /** @var false|string Whether a trace kept its frames' arguments before the test. */
    private false|string $ignoredArgs = false;

    /**
     * Keep every frame's arguments in a trace, and declare no session guard.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ignoredArgs = ini_get('zend.exception_ignore_args');

        ini_set('zend.exception_ignore_args', '0');

        Auth::swap(\Mockery::mock(AuthManager::class, ['sessionGuards' => []]));
    }

    /**
     * Restore the trace setting and the auth manager.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        ini_set('zend.exception_ignore_args', $this->ignoredArgs === false ? '0' : $this->ignoredArgs);

        Auth::clearResolvedInstances();

        parent::tearDown();
    }

    /**
     * Each redemption handed a code and a verifier.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction, \SineMacula\Laravel\Iam\Mfa\CurrentSession): mixed}>
     */
    public static function provideRedemptions(): iterable
    {
        $client = new ClientContext(null, null);

        yield 'a sign-in' => [static fn (CrossMemberTransaction $transaction, CurrentSession $sessions): mixed => (new SignInRedemption(
            new Container,
            $transaction,
            $sessions,
            new GroupSettings(new Container, new Repository),
            new IdentityReferences,
        ))->redeem('api', 'connection-1', self::CODE, self::VERIFIER, new SignInContext($client))];

        yield 'a re-authentication' => [static fn (CrossMemberTransaction $transaction, CurrentSession $sessions): mixed => (new ReauthenticationRedemption(
            new Container,
            $transaction,
            $sessions,
            new DecisionCacheInvalidation(new Container),
        ))->redeem('api', 'connection-1', self::CODE, self::VERIFIER, $client)];
    }

    /**
     * No frame of a trace thrown inside the transaction holds the secrets in
     * the clear.
     *
     * @param  \Closure(\SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction, \SineMacula\Laravel\Iam\Mfa\CurrentSession): mixed  $redemption
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRedemptions')]
    public function testNoFrameOfAThrownTraceHoldsTheSecretsInTheClear(\Closure $redemption): void
    {
        $thrown = null;

        try {
            $redemption($this->transaction(), new CurrentSession(\Mockery::mock(AuthFactory::class), \Mockery::mock(ConnectionResolverInterface::class)));
        } catch (UnresolvedReferenceException $exception) {
            $thrown = $exception;
        }

        self::assertNotNull($thrown, 'The redemption threw nothing inside its transaction.');

        $closures = 0;

        foreach ($thrown->getTrace() as $frame) {
            foreach ($frame['args'] ?? [] as $argument) {

                self::assertNotContains($argument, [self::CODE, self::VERIFIER], 'A frame holds a secret as an argument: ' . $frame['function']);

                if (!($argument instanceof \Closure)) {
                    continue;
                }

                $closures++;
                $this->assertHoldsNoSecret((new \ReflectionFunction($argument))->getStaticVariables());
            }
        }

        $printed = print_r($thrown->getTrace(), true);

        self::assertGreaterThan(0, $closures, 'No frame holds the work the transaction ran.');
        self::assertFalse(str_contains($printed, self::CODE), 'The printed trace holds the code.');
        self::assertFalse(str_contains($printed, self::VERIFIER), 'The printed trace holds the verifier.');
    }

    /**
     * Assert no value, nor any array member among them, is the code or the
     * verifier.
     *
     * @param  array<array-key, mixed>  $values
     * @return void
     */
    private function assertHoldsNoSecret(array $values): void
    {
        foreach ($values as $name => $value) {

            if (is_array($value)) {
                $this->assertHoldsNoSecret($value);

                continue;
            }

            self::assertNotContains($value, [self::CODE, self::VERIFIER], sprintf('The work captures a secret in the clear: $%s.', $name));
        }
    }

    /**
     * A cross-member transaction that runs the work once and rethrows its
     * failure.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction
     */
    private function transaction(): CrossMemberTransaction
    {
        $connection = \Mockery::mock(Connection::class);
        $database   = \Mockery::mock(DatabaseManager::class);

        $detector = \Mockery::mock(ConcurrencyErrorDetector::class);

        $connection->allows('transaction')->andReturnUsing(static fn (\Closure $work): mixed => $work());
        $database->allows('connection')->andReturn($connection);
        $detector->allows('causedByConcurrencyError')->andReturn(false);

        return new CrossMemberTransaction($database, new StorageConnection(new Repository), new Repository, $detector);
    }
}
