<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\Authorization\Support\Reference as AuthorizationReference;
use SineMacula\Laravel\Iam\Audit\References;

/**
 * Carries, on a deletion's record, the manifest of every grantee the deletion
 * took a grant from (IAM-9.2, AUTHZ-15.2), as audit-log's bulk record carries
 * the subjects of a bulk operation: each grantee once, read through the morph
 * map (`Audit\References`), under the bounds audit-log is configured with,
 * sealed as the record's attachment when it is written.
 *
 * Audit-log builds a bulk record's manifest only through `AuditLog::bulk()`,
 * which starts a builder of its own, so a mapper, which describes the builder
 * audit-log's capture hands it and writes nothing (IAM-9.4), reaches the same
 * three steps `bulk()` takes: the bound store is refused unless it keeps
 * attachments, the manifest is built under the configured bounds (refused,
 * never truncated, beyond them), and it is put on the record. A refusal is
 * thrown into audit-log's capture, which contains it as `AuditCaptureFailed`,
 * so it never reaches the change's caller, as a refused `bulk()` would not.
 *
 * A deletion that took no grant carries no manifest: audit-log refuses an empty
 * bulk operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GranteeManifests
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities  $store
     * @param  \SineMacula\Laravel\AuditLog\Capture\CaptureSettings  $settings
     */
    public function __construct(

        /** Says whether the bound store keeps a record's attachment. */
        private StoreCapabilities $store,

        /** Holds the bounds of a bulk operation's manifest. */
        private CaptureSettings $settings,
    ) {}

    /**
     * Put the manifest of the grantees on the record, when there is any.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    public function carry(PendingRecord $record, #[\SensitiveParameter] array $grantees): PendingRecord
    {
        if ($grantees === []) {
            return $record;
        }

        $this->store->assertAcceptsAttachments();

        $subjects = array_map(static fn (AuthorizationReference $grantee) => References::of($grantee->type, $grantee->id), $grantees);
        $manifest = Manifest::of(array_filter($subjects), $this->settings->bulkMaxMembers(), $this->settings->bulkMaxBytes());

        return $record->withManifest($manifest);
    }
}
