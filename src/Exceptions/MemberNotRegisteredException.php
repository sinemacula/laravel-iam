<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when the application finishes booting before a member whose storage
 * connection this package aligns has registered, so the member's key could
 * never be put on the shared connection, nor checked against it; or before
 * `laravel-audit-log` has registered, so this package's part of the audit trail
 * (its mappers, codes and caller context contributor) could never be registered
 * with it, and no member event would be recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class MemberNotRegisteredException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $key
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     */
    public function __construct(

        // What is missing, naming the member's provider and key.
        string $message,

        /** The member key that could not be aligned, or the key recording the registration that could not be made. */
        public readonly string $key,

        /** The member's service provider, which had not registered. */
        public readonly string $provider,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for a member whose provider had not registered when
     * the application finished booting, naming the provider and its storage
     * key.
     *
     * @param  string  $key
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @return self
     */
    public static function forStorage(string $key, string $provider): self
    {
        $message = '%s had not registered when the application finished booting, so %s could not be put on iam.storage.connection:'
            . ' every member keeps its tables on the one storage connection, so a change that spans members runs in one transaction.'
            . ' Register every member\'s service provider before the application finishes booting.';

        return new self(sprintf($message, $provider, $key), $key, $provider);
    }

    /**
     * Build an exception for `laravel-audit-log`, whose provider had not
     * registered when the application finished booting, so this package's part
     * of the audit trail, recorded under the given key once registered, could
     * not be registered with it.
     *
     * @param  string  $key
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @return self
     */
    public static function forAuditTrail(string $key, string $provider): self
    {
        $message = '%s had not registered when the application finished booting,'
            . ' so laravel-iam\'s audit mappers, codes and caller context contributor could not be registered with it:'
            . ' no authentication, MFA or SSO event would be recorded.'
            . ' Register every member\'s service provider before the application finishes booting.';

        return new self(sprintf($message, $provider), $key, $provider);
    }
}
