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
use Illuminate\Foundation\Auth\User;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Sso\Callers;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Iam\Transactions\RetrySettings;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use Tests\Fixtures\Sso\SessionGuards;

/**
 * Unit tests for the secrets a redemption is handed: the handoff code and its
 * verifier never reach a thrown exception's trace in the clear, neither as the
 * redemption's own arguments, which PHP redacts, nor in the work it hands the
 * transaction, whose captured values a trace carries as they are.
 *
 * Each redemption is made to throw inside its transaction, before SSO is asked
 * or as it is (a `link`, inside the caller's transaction), with the arguments
 * of every frame kept, as PHP's own default and its development settings keep
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRedemption::class)]
#[CoversClass(ReauthenticationRedemption::class)]
#[CoversClass(LinkRedemption::class)]
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
     * Keep every frame's arguments in a trace, as PHP's own default does.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ignoredArgs = ini_get('zend.exception_ignore_args');

        ini_set('zend.exception_ignore_args', '0');
    }

    /**
     * Restore whether a trace keeps its frames' arguments.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        ini_set('zend.exception_ignore_args', $this->ignoredArgs === false ? '0' : $this->ignoredArgs);

        parent::tearDown();
    }

    /**
     * Rows of `[redemption]`: each redemption handed a code and a verifier.
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
            new DecisionCacheInvalidation(new Container, \Mockery::mock(DatabaseManager::class)),
        ))->redeem('api', 'connection-1', self::CODE, self::VERIFIER, $client)];

        yield 'a link inside the caller\'s transaction' => [static fn (): mixed => self::linkInsideTheCallersTransaction()
            ->redeem('connection-1', self::CODE, self::VERIFIER, $client, self::caller())];
    }

    /**
     * An exception thrown inside the redemption's transaction carries neither
     * the code nor the verifier in the clear in any frame: not in a closure's
     * captured values, and not in what the trace prints.
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
            $redemption($this->transaction(), new CurrentSession(\Mockery::mock(AuthFactory::class), new Repository, \Mockery::mock(ConnectionResolverInterface::class)));
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
     * Assert none of the values, nor any value held in an array among them, is
     * the code or the verifier.
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
     * A cross-member transaction on a connection that opens and rolls back
     * nothing: it runs the work once, and rethrows its failure.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction
     */
    private function transaction(): CrossMemberTransaction
    {
        $connection = \Mockery::mock(Connection::class);
        $database   = \Mockery::mock(DatabaseManager::class);

        $connection->allows('transactionLevel')->andReturn(0);
        $connection->allows('beginTransaction');
        $database->allows('connection')->andReturn($connection);

        $failures = new ConcurrencyFailures(\Mockery::mock(ConcurrencyErrorDetector::class));

        return new CrossMemberTransaction($database, new StorageConnection(new Repository), new RetrySettings(new Repository), $failures);
    }

    /**
     * A link redemption for a session guard on a connection with the caller's
     * transaction open, whose savepoint runs the work once, and whose SSO
     * redemption fails as it is asked, so the work throws inside it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\LinkRedemption
     */
    private static function linkInsideTheCallersTransaction(): LinkRedemption
    {
        $connection = \Mockery::mock(Connection::class);
        $database   = \Mockery::mock(DatabaseManager::class);
        $container  = new Container;

        $connection->allows('transactionLevel')->andReturn(1);
        $connection->allows('transaction')->andReturnUsing(static fn (\Closure $work): mixed => $work());
        $database->allows('connection')->andReturn($connection);
        $container->bind(HandoffRedemption::class, static fn (): object => new class {
            /**
             * Fail as SSO's redemption is asked, keeping the code and the
             * verifier out of its frame as SSO's own redemption does.
             *
             * @param  mixed  $purpose
             * @param  mixed  $application
             * @param  mixed  $connectionId
             * @param  mixed  $code
             * @param  mixed  $verifier
             * @return never
             *
             * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
             */
            public function redeem(mixed $purpose, mixed $application, mixed $connectionId, #[\SensitiveParameter] mixed $code, #[\SensitiveParameter] mixed $verifier): never
            {
                unset($purpose, $connectionId, $code, $verifier);

                throw UnresolvedReferenceException::forGuard(is_string($application) ? $application : 'api');
            }
        });

        $storage  = new StorageConnection(new Repository);
        $settings = new RetrySettings(new Repository);
        $failures = new ConcurrencyFailures(\Mockery::mock(ConcurrencyErrorDetector::class));

        $transaction = new CrossMemberTransaction($database, $storage, $settings, $failures);

        return new LinkRedemption($container, new Callers(new IdentityReferences, SessionGuards::resolving('api')), $database, $storage, $settings, $failures, $transaction);
    }

    /**
     * The caller a link is redeemed as: an Eloquent identity with a key, on the
     * `api` guard, holding no session.
     *
     * @return \SineMacula\Laravel\Authentication\Callers\Caller
     */
    private static function caller(): Caller
    {
        return new Caller('api', CallerCredential::ACCESS, (new class extends User implements Identity {})->forceFill(['id' => 7]), null, null, null);
    }
}
