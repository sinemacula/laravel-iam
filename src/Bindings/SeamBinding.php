<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Container\Container;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * One member seam this package binds an adapter over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeamBinding
{
    /** @var string Prefix of the keys scoped adapters are held under, apart from the seam. */
    public const string SCOPED_PREFIX = 'iam.scoped:';

    /**
     * Constructor.
     *
     * @param  class-string  $abstract
     * @param  class-string  $adapter
     * @param  bool  $on
     * @param  \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime  $lifetime
     * @param  bool|\Closure(): bool  $mandatory
     * @param  ?\Closure(\Illuminate\Container\Container, \Closure(\Illuminate\Container\Container): mixed): void  $declare
     */
    public function __construct(

        /** The member's contract. */
        public string $abstract,

        /** This package's implementation of it. */
        public string $adapter,

        /** Whether the adapter is bound at all. */
        public bool $on = true,

        /** How long the container keeps the adapter. */
        public Lifetime $lifetime = Lifetime::TRANSIENT,

        /** Whether `iam:check` refuses the member's default; a closure is asked lazily. */
        public bool|\Closure $mandatory = false,

        /** Declares the bound adapter to the member. */
        public ?\Closure $declare = null,
    ) {}

    /**
     * Whether `iam:check` refuses the member's default on this seam.
     *
     * @return bool
     */
    public function isMandatory(): bool
    {
        return $this->mandatory instanceof \Closure ? ($this->mandatory)() : $this->mandatory;
    }

    /**
     * Whether the seam still holds its member's own default.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function holdsDefault(Container $container): bool
    {
        $member = match (true) {
            str_starts_with($this->abstract, 'SineMacula\Laravel\Authentication\\') => AuthenticationServiceProvider::class,
            str_starts_with($this->abstract, 'SineMacula\Laravel\Authorization\\')  => AuthorizationServiceProvider::class,
            str_starts_with($this->abstract, 'SineMacula\Laravel\Mfa\\')            => MfaServiceProvider::class,
            str_starts_with($this->abstract, 'SineMacula\Laravel\Sso\\')            => SsoServiceProvider::class,
            str_starts_with($this->abstract, 'SineMacula\Laravel\AuditLog\\')       => AuditLogServiceProvider::class,
            default                                                                 => throw new \InvalidArgumentException($this->abstract . ' is no member\'s contract.'),
        };

        return $member::isPackageDefault($container, $this->abstract);
    }

    /**
     * Bind the adapter unless the application bound the seam itself.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function apply(Container $container): void
    {
        if (!$this->on || ($container->bound($this->abstract) && !$this->holdsDefault($container))) {
            return;
        }

        $key = $this->adapter;

        if ($this->lifetime === Lifetime::SCOPED) {
            $key = self::SCOPED_PREFIX . $this->abstract;

            $container->scoped($key, $this->adapter);
        }

        $concrete = static fn (Container $container): mixed => $container->make($key);

        $container->bind($this->abstract, $concrete, $this->lifetime === Lifetime::SHARED);

        if ($this->declare === null) {
            return;
        }

        ($this->declare)($container, $concrete);
    }
}
