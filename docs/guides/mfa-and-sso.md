# MFA and SSO

An identity provider may report how it authenticated the person: its `amr` values, an `acr`, or SAML's authentication
context class. Whether that counts towards a further factor is a decision in two parts, made by two members, and this
package keeps them apart. By default neither counts anything, so a person who signs in through SSO owes the same
further factor as one who signs in with a password.

SSO's side is in its [provider evidence guide][sso-evidence] and its [guide for this package][sso-iam-evidence]; MFA's
in its [assurance guide][mfa-assurance].

## The two gates

1. **SSO accepts the provider's evidence.** SSO's `EvidencePolicy` decides, at redemption, which of the provider's own
   assertions count at all, per connection and within `sso.linking.evidence_max_age_seconds`. Its default accepts
   nothing. Turn on SSO's per-connection policy with the package's switch:

   ```dotenv
   IAM_SSO_EVIDENCE=true
   ```

   The package then binds SSO's `SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy`, which accepts what each
   connection's evidence settings list (`Sso\Connections\EvidenceSettingsService`, with `sso.connection.trust`
   freshness). Only `true` turns it on, and it never replaces an evidence policy you bound yourself.

2. **MFA decides what accepted evidence satisfies.** The package hands `laravel-authentication` only what SSO accepted,
   and answers `laravel-authentication`'s external evidence policy with MFA's `CombinationPolicy`, judging the sign-in
   as MFA records it: a `first_factor` proof on an `external_provider` channel that names the connection. MFA's default
   classifies nothing an external provider reports, so with the first gate open a provider's `mfa` is still not
   multifactor authentication, an additional verification, a level or phishing resistance.

To trust a provider, rebind MFA's combination policy (see MFA's [assurance guide][mfa-assurance-rebinding]) so it
classifies a first factor on the `external_provider` channel of that connection. The provider's methods themselves
never reach MFA, since its proof carries none: a rebound policy trusts a provider by its connection, never by the
`amr` it sent. A member gap; see the [SSO design note](../design/sso-redemption-and-revocation.md#member-gaps).

Trusting the connection in the combination policy does not go around the first gate. Every SSO sign-in records its
first factor on the connection's `external_provider` channel, whatever SSO accepted, so the package decides, by a rule
of its own you cannot rebind, when MFA sees that channel name the connection:

- MFA's own judgements of a session (its route gate, `mfa` and `mfa:level=...`, the further factor it asks for at
  sign-in, a pending sign-in's completion and its reauthenticator) see the connection only when the session's first
  factor carries evidence SSO accepted and, for a session acting in a tenant, the tenant trusts the connection. Any other
  SSO first factor reaches MFA naming no connection, so the rebound policy counts nothing of it;
- `laravel-authentication`'s requirement check never sees the connection: `laravel-authentication` asks its external
  evidence policy first, with the tenant whose requirement it is, and that policy counts the accepted evidence through
  both gates and that tenant's trust.

So a password-only sign-in through a trusted connection, or one SSO's evidence policy refused, meets no multifactor
requirement, and one tenant's trust in a connection never meets another tenant's requirement.

Opening both gates widens what an SSO session can satisfy without a factor of its own. Do it only for connections whose
provider you trust to enforce the methods it reports.

## What accepted evidence reaches

The evidence is offered to the identity's own requirement at sign-in and to the requirement of the tenant the session
acts in, at sign-in and on every later judgement of the session:

- evidence counts only as the evidence SSO accepted in the redemption admitted in the same request, for the identity
  that redemption linked, with its own methods and time; evidence handed to `laravel-authentication` by any other path
  is never accepted;
- for a tenant, the connection must be one the tenant trusts as well: one of its own, or one its enforcement names. One
  tenant's trust in a connection is never another's;
- MFA's route gate counts the same evidence, judged by the combination policy, for the tenant the session acts in, and
  counts nothing of an SSO sign-in whose first factor carries no accepted evidence;
- a requirement's maximum age is judged from the evidence's time, so stale evidence stops meeting it.

When the evidence does not meet the requirement, the session starts pending and the person verifies a factor of
MFA's, as after any sign-in (see [Authentication and MFA](authentication-and-mfa.md#signing-in-with-a-further-factor)).

## Re-authentication at the provider

A `reauthenticate` redemption (see [Authentication and SSO](authentication-and-sso.md#re-authenticating)) is recorded
on the session as a reauthentication at the provider, which MFA reads as a `first_factor_reauthentication` on the
connection's channel. It renews the session's authentication time; earlier evidence stays unless this
authentication's own evidence was accepted. `laravel-authentication`'s `first_additional_factor` freshness takes a
reauthentication at an external provider, so a person who signed in through SSO can re-authenticate there before
enrolling their first factor. `laravel-authorization`'s authentication requirements read it as MFA's route gate does,
so a policy statement's `max_age` is renewed by it wherever a route's is (see
[Authorization](authorization.md#authentication-requirements)).

## Tenants that require a factor

A tenant's requirement comes from your implementation of laravel-mfa's `TenantRequirement` (see
[Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-mfa-requirement)), and is folded into the tenant
policy with SSO's enforcement. A tenant that enforces SSO and requires a further factor is met by a session through one
of the connections its rule accepts, once both gates accept that session's evidence for the requirement or the person
has verified a factor of MFA's on it.

## Further reading

- [The SSO redemption and revocation design note](../design/sso-redemption-and-revocation.md).
- [The tenant authentication policy design note](../design/tenant-authentication-policy.md).

[sso-evidence]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/evidence.md
[sso-iam-evidence]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/integrating-with-laravel-iam.md#evidence-and-laravel-mfa
[mfa-assurance]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/assurance.md
[mfa-assurance-rebinding]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/assurance.md#rebinding-the-policy
