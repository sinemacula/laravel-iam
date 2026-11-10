<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization\Enums;

/**
 * The administrative operations of SSO and MFA this package's permission
 * catalogue declares (IAM-6.9, AUTHZ-14.5), each a permission name the
 * application grants and checks before the member's call
 * (`AdministrativeCheck`), with the member's object as the resource.
 *
 * Where SSO names an operation itself (its freshness-gated operations,
 * `Freshness\Enums\FreshnessOperation`), the case is that name, so one name
 * means one operation across the suite. SSO's other administration and every
 * one of MFA's is named here, under the member's prefix, since neither member
 * names it. An operation on another identity's object is a different action
 * from the same operation on the caller's own (removing someone else's link),
 * so it has its own case.
 *
 * MFA's re-enabling of a factor disabled at the failure ceiling
 * (`Attempts\AttemptService::enableFactor()`) is `mfa.factor.enable`; its
 * requirements are the application's own contracts, so managing them is the
 * application's operation, declared here so it can be granted with the rest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum AdministrativeOperation: string
{
    // Create a connection
    case SSO_CONNECTION_CREATE = 'sso.connection.create';

    // Change a connection's settings
    case SSO_CONNECTION_UPDATE = 'sso.connection.update';

    // Change what evidence a connection asks of its provider
    case SSO_CONNECTION_EVIDENCE = 'sso.connection.evidence';

    // Change how a connection links people
    case SSO_CONNECTION_LINKING_POLICY = 'sso.connection.linking_policy';

    // Import a provider's metadata or discovery document into a connection
    case SSO_CONNECTION_IMPORT = 'sso.connection.import';

    // Trust a connection
    case SSO_CONNECTION_TRUST = 'sso.connection.trust';

    // Enable a connection
    case SSO_CONNECTION_ENABLE = 'sso.connection.enable';

    // Disable a connection
    case SSO_CONNECTION_DISABLE = 'sso.connection.disable';

    // Delete a connection
    case SSO_CONNECTION_DELETE = 'sso.connection.delete';

    // Allow sign-ins a connection's provider starts
    case SSO_CONNECTION_IDP_INITIATED = 'sso.connection.idp_initiated';

    // Move a connection's links to another subject attribute
    case SSO_CONNECTION_MIGRATE_SUBJECTS = 'sso.connection.migrate_subjects';

    // Rotate a connection's keys: add the next, make it current, retire one
    case SSO_KEYS_ROTATE = 'sso.keys.rotate';

    // Trust a provider's certificate
    case SSO_KEYS_TRUST_CERTIFICATE = 'sso.keys.trust_certificate';

    // Stop trusting a provider's certificate
    case SSO_KEYS_DISTRUST_CERTIFICATE = 'sso.keys.distrust_certificate';

    // Claim a domain
    case SSO_DOMAIN_CLAIM = 'sso.domain.claim';

    // Verify a domain
    case SSO_DOMAIN_VERIFY = 'sso.domain.verify';

    // Remove a domain
    case SSO_DOMAIN_REMOVE = 'sso.domain.remove';

    // Change a tenant's enforcement
    case SSO_ENFORCEMENT_UPDATE = 'sso.enforcement.update';

    // Link one's own identity to a provider's account
    case SSO_LINK_CREATE = 'sso.link.create';

    // Remove one's own link
    case SSO_LINK_REMOVE = 'sso.link.remove';

    // Remove another identity's link
    case SSO_LINK_REMOVE_OTHERS = 'sso.link.remove_others';

    // Reset an identity's factors
    case MFA_IDENTITY_RESET = 'mfa.identity.reset';

    // Lift an identity's lockout
    case MFA_IDENTITY_UNLOCK = 'mfa.identity.unlock';

    // Lift a factor's lockout
    case MFA_FACTOR_UNLOCK = 'mfa.factor.unlock';

    // Re-enable a factor disabled at the failure ceiling
    case MFA_FACTOR_ENABLE = 'mfa.factor.enable';

    // Erase an identity's MFA data
    case MFA_IDENTITY_ERASE = 'mfa.identity.erase';

    // Manage the MFA requirements the application answers for an identity or a
    // tenant
    case MFA_REQUIREMENTS_MANAGE = 'mfa.requirements.manage';

    /**
     * The member whose operation this is: `sso` or `mfa`, the category the
     * catalogue declares it under.
     *
     * @return string
     */
    public function member(): string
    {
        return explode('.', $this->value)[0];
    }
}
