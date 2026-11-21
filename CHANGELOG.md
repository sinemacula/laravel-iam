# Changelog

## 0.1.0 (2026-11-21)

First release. Identity and access management for Laravel: installs the authentication, authorization, MFA, SSO and
audit log packages and binds them together, translating between their shapes, mapping their events to the audit trail
and checking that the whole is configured safely.

### Features

* one `composer require` for the five member packages
* a shared storage connection, so a change that spans members commits or rolls back as one, with retries on concurrency failures and worker state reset between units of work
* laravel-authentication's sessions behind laravel-mfa's proof store, session transitions, factor change gates and code challenges
* sessions started with a first factor, and SSO links confirmed from MFA proofs and recovery sessions
* authorization decided for the suite's caller, its proofs and its credential scopes, with MFA requirements on permissions
* tenant grants, scopes, the tenant tree, group-to-role mapping and cache invalidation wired into laravel-authorization
* the tenant authentication policy answered from SSO's enforcement and MFA's tenant requirement
* SSO handoffs redeemed through laravel-authentication, with linking, just-in-time provisioning and session revocation
* MFA codes delivered through laravel-authentication's code sender, and passkeys shared between authentication and MFA
* an audit trail of the authentication, authorization, MFA and SSO events, with access to it decided by authorization
* `iam:install`, `iam:check` across every member, and the members' scheduled work
* acting as a signed-in caller across the suite in one call for tests, and guides with example route layouts
