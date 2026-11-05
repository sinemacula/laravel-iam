<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when the application finishes booting before a member whose storage
 * connection this package aligns has registered, so the member's key could
 * never be put on the shared connection, nor checked against it.
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

        /** The member key that could not be aligned. */
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
}
