<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when the application boots with a member's storage connection naming a
 * different connection from the one this package configures, so a change that
 * spans members could not run in one transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class StorageConnectionMismatchException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $key
     * @param  ?string  $member
     * @param  ?string  $storage
     */
    public function __construct(

        // What differs, naming both connections.
        string $message,

        /** The member key that names another connection. */
        public readonly string $key,

        /** The connection the member key names; `null` for the default connection. */
        public readonly ?string $member,

        /** The connection `iam.storage.connection` names; `null` for the default connection. */
        public readonly ?string $storage,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for a member key that names another connection, naming
     * the key and both connections.
     *
     * @param  string  $key
     * @param  ?string  $member
     * @param  ?string  $storage
     * @return self
     */
    public static function forKey(string $key, ?string $member, ?string $storage): self
    {
        $message = '%s names [%s], but iam.storage.connection names [%s]: every member keeps its tables on the one storage connection,'
            . ' so a change that spans members runs in one transaction. Unset the member key, or set it to the same connection.';

        return new self(sprintf($message, $key, $member ?? 'default', $storage ?? 'default'), $key, $member, $storage);
    }
}
