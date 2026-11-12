<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization\Enums;

/**
 * The SSO and MFA administrative operations the permission catalogue declares;
 * SSO's freshness-gated operations keep SSO's own names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum AdministrativeOperation: string
{
    case SSO_CONNECTION_CREATE           = 'sso.connection.create';
    case SSO_CONNECTION_UPDATE           = 'sso.connection.update';
    case SSO_CONNECTION_EVIDENCE         = 'sso.connection.evidence';
    case SSO_CONNECTION_LINKING_POLICY   = 'sso.connection.linking_policy';
    case SSO_CONNECTION_IMPORT           = 'sso.connection.import';
    case SSO_CONNECTION_TRUST            = 'sso.connection.trust';
    case SSO_CONNECTION_ENABLE           = 'sso.connection.enable';
    case SSO_CONNECTION_DISABLE          = 'sso.connection.disable';
    case SSO_CONNECTION_DELETE           = 'sso.connection.delete';
    case SSO_CONNECTION_IDP_INITIATED    = 'sso.connection.idp_initiated';
    case SSO_CONNECTION_MIGRATE_SUBJECTS = 'sso.connection.migrate_subjects';
    case SSO_KEYS_ROTATE                 = 'sso.keys.rotate';
    case SSO_KEYS_TRUST_CERTIFICATE      = 'sso.keys.trust_certificate';
    case SSO_KEYS_DISTRUST_CERTIFICATE   = 'sso.keys.distrust_certificate';
    case SSO_DOMAIN_CLAIM                = 'sso.domain.claim';
    case SSO_DOMAIN_VERIFY               = 'sso.domain.verify';
    case SSO_DOMAIN_REMOVE               = 'sso.domain.remove';
    case SSO_ENFORCEMENT_UPDATE          = 'sso.enforcement.update';
    case SSO_LINK_CREATE                 = 'sso.link.create';
    case SSO_LINK_REMOVE                 = 'sso.link.remove';
    case SSO_LINK_REMOVE_OTHERS          = 'sso.link.remove_others';
    case MFA_IDENTITY_RESET              = 'mfa.identity.reset';
    case MFA_IDENTITY_UNLOCK             = 'mfa.identity.unlock';
    case MFA_FACTOR_UNLOCK               = 'mfa.factor.unlock';
    case MFA_FACTOR_ENABLE               = 'mfa.factor.enable';
    case MFA_IDENTITY_ERASE              = 'mfa.identity.erase';
    case MFA_REQUIREMENTS_MANAGE         = 'mfa.requirements.manage';

    /**
     * The member whose operation this is: `sso` or `mfa`.
     *
     * @return string
     */
    public function member(): string
    {
        return explode('.', $this->value)[0];
    }
}
