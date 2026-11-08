<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Enums;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;

/**
 * The `authentication.*` codes `laravel-authentication`'s events are recorded
 * under that audit-log does not ship (IAM-9.2): the refusal of each flow but a
 * sign-in's, named by its flow, a sign-in refused for a reason concealed from
 * the client, an external provider's result redeemed or unlinked, identifier
 * and password changes, passkeys, API keys and client credentials.
 *
 * Audit-log's own codes are reused for an event that means the same, with their
 * definitions unchanged, and never defined here: a person signing in
 * (`authentication.signed_in`), a sign-in refused (`sign_in_failed`), a sign-in
 * refused once its attempts are used up (`locked_out`), a user's own sign-out
 * (`signed_out`), an email address verified (`account.email_verified`) and a
 * password reset (`account.password_reset`). A sign-in refused for a concealed
 * reason needs its `concealed` flag kept, which `sign_in_failed` drops, so it
 * has a code of its own.
 *
 * Every definition is version 1, in the `security` category, and drops every
 * property it does not list. A refusal keeps the sign-in method, the wait of a
 * rate-limited one, and whether its reason is concealed, so it is never
 * rendered to an end user; the identifier a sign-in named is hashed by
 * audit-log, never kept. An identifier an identifier change names is
 * pseudonymised: kept as a keyed hash, so records of one identifier can be
 * matched without holding it. A passkey's addition and removal keep the
 * passkey's id (`passkey_id`), and an API key's issue, revocation and rotation
 * the key's (`key_id`), since the credential they manage is not one the
 * activity used; an API key's management, left to the caller, keeps the
 * principal the key acts as (`key_principal_type`, `key_principal_id`), since
 * the record's principal is the caller's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum AuthenticationActivity: string implements ListsProperties
{
    // A sign-in was refused for a reason concealed from the client
    case SIGN_IN_FAILED_CONCEALED = 'authentication.sign_in_failed_concealed';

    // A request's access token was refused
    case REQUEST_REJECTED = 'authentication.request_rejected';

    // A request's API key was refused
    case API_KEY_REJECTED = 'authentication.api_key_rejected';

    // A client credentials exchange was refused
    case CLIENT_CREDENTIALS_FAILED = 'authentication.client_credentials_failed';

    // A request for a one-time code was refused
    case CODE_REQUEST_FAILED = 'authentication.code_request_failed';

    // An identifier verification code or link was refused
    case IDENTIFIER_VERIFICATION_FAILED = 'authentication.identifier_verification_failed';

    // A password reset, or a request for one, was refused
    case PASSWORD_RESET_FAILED = 'authentication.password_reset_failed';

    // A change of identifier, or a request for one, was refused
    case IDENTIFIER_CHANGE_FAILED = 'authentication.identifier_change_failed';

    // A further factor's code, or a request for one, was refused
    case FACTOR_CODE_FAILED = 'authentication.factor_code_failed';

    // A change or an establishment of the password was refused
    case PASSWORD_CHANGE_FAILED = 'authentication.password_change_failed';

    // An external provider's result was redeemed into a sign-in or a
    // reauthentication
    case EXTERNAL_RESULT_REDEEMED = 'authentication.external_result_redeemed';

    // An external provider's result linked to no identity
    case EXTERNAL_RESULT_UNLINKED = 'authentication.external_result_unlinked';

    // A change of identifier was requested
    case IDENTIFIER_CHANGE_REQUESTED = 'authentication.identifier_change_requested';

    // An identifier was changed
    case IDENTIFIER_CHANGED = 'authentication.identifier_changed';

    // An identifier other than an email address was verified
    case IDENTIFIER_VERIFIED = 'authentication.identifier_verified';

    // An identity's first password was set at registration
    case PASSWORD_SET = 'authentication.password_set';

    // A signed-in identity changed its password
    case PASSWORD_CHANGED = 'authentication.password_changed';

    // A signed-in identity with no password established one
    case PASSWORD_ESTABLISHED = 'authentication.password_established';

    // A passkey was added
    case PASSKEY_ADDED = 'authentication.passkey_added';

    // A passkey was removed
    case PASSKEY_REMOVED = 'authentication.passkey_removed';

    // A passkey was used
    case PASSKEY_USED = 'authentication.passkey_used';

    // An API key was issued
    case API_KEY_ISSUED = 'authentication.api_key_issued';

    // An API key was revoked
    case API_KEY_REVOKED = 'authentication.api_key_revoked';

    // An API key was rotated
    case API_KEY_ROTATED = 'authentication.api_key_rotated';

    // A client credentials exchange granted an access token
    case CLIENT_CREDENTIALS_GRANTED = 'authentication.client_credentials_granted';

    /** @var string The category every authentication code is stored under. */
    private const string CATEGORY = 'security';

    /** @var list<string> What every refusal keeps. */
    private const array REFUSAL = ['method', 'retry_after', 'concealed'];

    /** @var list<string> What an API key's management keeps: the key managed, its scopes and the principal it acts as. */
    private const array KEY = ['scopes', 'key_id', 'key_principal_type', 'key_principal_id'];

    /**
     * The definition of this case's code: version 1, the `security` category,
     * the properties it lists kept, an identifier change's identifiers
     * pseudonymised, and every other property dropped.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for($this)
            ->category(self::CATEGORY)
            ->retain(...$this->retained())
            ->pseudonymise(...$this->pseudonymised());
    }

    /**
     * Every property this case's code keeps.
     *
     * @return list<string>
     */
    #[\Override]
    public function properties(): array
    {
        return [...$this->retained(), ...$this->pseudonymised()];
    }

    /**
     * The properties this case's code keeps as captured.
     *
     * @return list<string>
     */
    private function retained(): array
    {
        return match ($this) {
            self::EXTERNAL_RESULT_REDEEMED    => ['flow', 'method', 'connection_id'],
            self::EXTERNAL_RESULT_UNLINKED    => ['method', 'connection_id', 'issuer'],
            self::IDENTIFIER_CHANGE_REQUESTED => ['type', 'expires_at'],
            self::IDENTIFIER_CHANGED,
            self::IDENTIFIER_VERIFIED => ['type'],
            self::PASSWORD_SET,
            self::PASSWORD_CHANGED,
            self::PASSWORD_ESTABLISHED,
            self::PASSKEY_USED               => ['method'],
            self::CLIENT_CREDENTIALS_GRANTED => ['scopes'],
            default                          => $this->management() ?? self::REFUSAL,
        };
    }

    /**
     * The properties this case's code keeps when it records a credential's
     * management: the credential managed, and an API key's scopes and the
     * principal it acts as; `null` for any other code.
     *
     * @return ?list<string>
     */
    private function management(): ?array
    {
        return match ($this) {
            self::PASSKEY_ADDED,
            self::PASSKEY_REMOVED => ['method', 'passkey_id'],
            self::API_KEY_ISSUED,
            self::API_KEY_REVOKED => self::KEY,
            self::API_KEY_ROTATED => [...self::KEY, 'previous_key_id'],
            default               => null,
        };
    }

    /**
     * The properties this case's code keeps only as keyed hashes.
     *
     * @return list<string>
     */
    private function pseudonymised(): array
    {
        return match ($this) {
            self::IDENTIFIER_CHANGE_REQUESTED => ['identifier'],
            self::IDENTIFIER_CHANGED          => ['previous', 'identifier'],
            default                           => [],
        };
    }
}
