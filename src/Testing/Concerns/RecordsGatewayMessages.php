<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Concerns;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;

/**
 * What a fake gateway keeps: every code message it is given, oldest first,
 * instead of delivering it, so a test can read the code a member sent and
 * verify with it, and see what else the message said; and, when told to, a
 * failure in place of the next delivery. A fake using it names the contract it
 * is bound as in its `GATEWAY` constant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsGatewayMessages
{
    /** @var list<\SineMacula\Laravel\Iam\Delivery\CodeMessage> The messages sent, oldest first. */
    private array $sent = [];

    /** @var ?\Throwable The failure the next delivery throws instead of keeping its message. */
    private ?\Throwable $failure = null;

    /**
     * Bind a fresh fake as the gateway in the container (the application's,
     * when none is given) and return it. The adapters resolve the gateway on
     * every code, so the next code goes to the fake; the application still
     * names a gateway, or binds one before this package registers, for the
     * adapters to be bound at all.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        ($container ?? Container::getInstance())->instance(self::GATEWAY, $fake);

        return $fake;
    }

    /**
     * Keep the message instead of delivering it, or throw the failure the fake
     * was told to, keeping nothing.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\CodeMessage  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $failure       = $this->failure;
        $this->failure = null;

        if ($failure !== null) {
            throw $failure;
        }

        $this->sent[] = $message;
    }

    /**
     * Fail the next delivery with the exception given, or a `RuntimeException`
     * that names neither the code nor the destination, keeping nothing; the
     * delivery after it is kept again.
     *
     * @param  ?\Throwable  $exception
     * @return self
     */
    public function failNext(?\Throwable $exception = null): self
    {
        $this->failure = $exception ?? new \RuntimeException('The fake gateway was told to fail this delivery.');

        return $this;
    }

    /**
     * Every message sent, oldest first, or those of them the filter accepts.
     *
     * @param  (\Closure(\SineMacula\Laravel\Iam\Delivery\CodeMessage): bool)|null  $filter
     * @return list<\SineMacula\Laravel\Iam\Delivery\CodeMessage>
     *
     * @phpstan-impure
     */
    public function sent(?\Closure $filter = null): array
    {
        return $filter === null ? $this->sent : array_values(array_filter($this->sent, $filter));
    }

    /**
     * The messages sent to the destination, in its normal form, oldest first.
     *
     * @param  string  $destination
     * @return list<\SineMacula\Laravel\Iam\Delivery\CodeMessage>
     *
     * @phpstan-impure
     */
    public function sentTo(#[\SensitiveParameter] string $destination): array
    {
        return $this->sent(static fn (CodeMessage $message): bool => $message->destination() === $destination);
    }

    /**
     * The code last sent to the destination, for the purpose when one is given,
     * revealed for the test to submit; `null` when none was.
     *
     * @param  string  $destination
     * @param  ?\SineMacula\Laravel\Iam\Delivery\Enums\Purpose  $purpose
     * @return ?string
     */
    public function lastCodeTo(#[\SensitiveParameter] string $destination, ?Purpose $purpose = null): ?string
    {
        $sent = $this->sent(static fn (CodeMessage $message): bool => $message->destination() === $destination && ($purpose === null || $message->purpose === $purpose));

        return $sent === [] ? null : $sent[count($sent) - 1]->code->reveal();
    }

    /**
     * Forget every message sent so far, and any failure the fake was told to
     * throw.
     *
     * @return void
     */
    public function reset(): void
    {
        $this->sent    = [];
        $this->failure = null;
    }
}
