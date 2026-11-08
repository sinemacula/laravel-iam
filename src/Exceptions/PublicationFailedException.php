<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when `iam:install` cannot copy a file to where its provider publishes
 * it (IAM-2.1): the run stops there, every file published before it is kept,
 * and running the command again, once the path is writable, publishes the rest
 * and nothing twice. The message names the path, never the file's contents;
 * the warning that stopped the copy is kept as the previous exception, an
 * `\ErrorException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PublicationFailedException extends \RuntimeException
{
    /**
     * Build an exception for a file that could not be copied, with the error
     * that stopped it, when one was raised.
     *
     * @param  string  $destination
     * @param  ?\Throwable  $previous
     * @return self
     */
    public static function forFile(string $destination, ?\Throwable $previous = null): self
    {
        return new self(sprintf('%s could not be published; make its directory writable and run iam:install again.', $destination), 0, $previous);
    }
}
