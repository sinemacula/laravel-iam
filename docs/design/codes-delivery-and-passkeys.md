# Codes, Delivery and Passkeys

## Purpose

How the package joins `laravel-authentication` and `laravel-mfa` for code challenges, code delivery, passkeys as
factors and the context MFA reads. The other MFA seams and the lock order are in `authentication-and-mfa.md`.

## Seams

All rows are transient, replace only their member's default, and are on while `iam.adapters.mfa` is.

| Member seam                | Adapter                       | Member default                | Table          |
| -------------------------- | ----------------------------- | ----------------------------- | -------------- |
| MFA `ChallengeGateway`     | `ChallengeGatewayAdapter`     | `PackageChallengeGateway`     | `MfaSeams`     |
| AUTH `FactorCodeCounters`  | `FactorCodeCountersAdapter`   | `RefuseFactorCodes`           | `MfaSeams`     |
| MFA `SmsSender`            | `CodeSenderAdapter`           | `NullSmsSender`               | `MfaSeams`     |
| MFA `EmailSender`          | `CodeSenderAdapter`           | `NullEmailSender`             | `MfaSeams`     |
| MFA `PasskeyGateway`       | `PasskeyGatewayAdapter`       | `UnavailablePasskeyGateway`   | `PasskeySeams` |
| AUTH `PasskeyFactorGate`   | `PasskeyFactorGateAdapter`    | `NoPasskeyFactors`            | `PasskeySeams` |
| MFA `EventContextResolver` | `EventContextResolverAdapter` | `DefaultEventContextResolver` | `ContextSeams` |
| MFA `ActiveTenantResolver` | `ActiveTenantResolverAdapter` | `NoActiveTenant`              | `ContextSeams` |
| MFA `SubjectTypeResolver`  | `SubjectTypeResolverAdapter`  | `IdentityContractSubjectType` | `ContextSeams` |
| MFA `ActiveStateResolver`  | `ActiveStateResolverAdapter`  | `IdentityContractActiveState` | `ContextSeams` |
| MFA `ApplicationResolver`  | `ApplicationResolverAdapter`  | none (while unbound)          | `ContextSeams` |

- The passkey gateway is bound only while an MFA application offers the `passkey` type.
- The passkey factor gate is mandatory and bound whenever the switch is on. A passkey enrolled as a factor stays one
  after the type is withdrawn, and on `NoPasskeyFactors` removing it would leave its factor standing.
- The active tenant resolver is mandatory while SSO's enforcement is on or the application binds MFA's tenant
  requirement; otherwise no tenant's requirement reaches MFA.

## Decisions

- Codes for every factor whose driver's channel kind is `sms` or `email` are sent and checked through
  `Auth::codes()`'s factor codes; any other kind, and a `reauthenticate` binding, is `not_accepted`. An application that
  wants MFA's own challenges rebinds `ChallengeGateway`.
- The factor code binding names the factor by id and its own channel and destination. An enrolment's grant is the
  pending factor's id, since MFA never hands its grant out.
- `FactorCodeCountersAdapter` answers authentication's counters with MFA's `ChallengeCounters`, inside
  authentication's transaction. A binding whose channel is not the factor's own is `not_found` without asking MFA, so no
  code goes to another number or address.
- Outcomes: authentication's `invalid` (a wrong or malformed code) is MFA's counted `invalid_code`, since only a counted
  failure keeps its count when a refusal rolls back. `not_found` stays `not_found` and `replayed` stays `replayed`;
  `used` (another code at a used challenge, or an ended one) is an uncounted `invalid_code`; `expired` and `exhausted`
  are `expired`; `locked` and `rate_limited` are `locked`. A send that is `rate_limited` or `deliveries_exhausted` is
  `sending_capped`. A wrong code that caused a lockout is answered locked until it ends.
- Delivery: MFA's SMS and email senders forward each `CodeMessage` to the application's `OneTimeCodeSender` as a
  `OneTimeCodeMessage` with purpose `enrollment` or `mfa`. The package composes no text and queues nothing. MFA's boot
  check builds its senders, so boot is refused until a `OneTimeCodeSender` is bound.
- Passkey ceremonies run through `laravel-authentication`'s `factorOptions()` and `verifyFactor()` on the binding's
  guard. A request allowing none of the identity's passkeys is refused, since the browser would offer any credential it
  holds. `passkey_challenge_used` is `replayed`, `passkey_challenge_expired` and `passkey_challenge_invalid` are
  `expired`, and every other failure is `invalid_code`.
- The passkey factor gate calls MFA's `PasskeyChangeGate` inside authentication's passkey transaction, before the
  passkey row is written or deleted, so a passkey and its factor never part. A registration with no binding stays a
  sign-in passkey; one bound for anything but enrolment is refused. A bootstrap enrolment on a pending sign-in is
  completed through the pending completion in the same change.
- Context resolvers read what MFA hands them, or the guard's validated session, never `Auth::caller()`, a request or a
  claim:
  - the application is the guard MFA names, else the default guard;
  - the active tenant is the validated session's `tenant_id`, and none before the session exists, since authentication
    asks MFA's requirement during sign-in;
  - an event's context names the session, principal and tenant only when the sign-in MFA names is the identity's on
    that guard, and never throws;
  - a `MachineIdentity` is never a person;
  - an identity authentication can deactivate is active as `ActivationPolicy::isActive()` says, read on the primary.

## Invariants

- A challenge takes MFA's identity state, then its factors, then the session row, then authentication's `rate_limits`
  rows, then the `one_time_codes` row. Every path holds the identity state first, so none deadlock.
- The code limit rows are written inside MFA's transaction, so a refused check commits its count.
- A passkey registration or removal takes MFA's identity state and factors, and the session row for a transition or a
  revocation, before the passkey row.
- Each code send and check is handed the caller's client, so authentication's limits and events are the caller's.

## Member gaps

- `laravel-authentication`: `FactorCodeCounters::admit()` and `report()` receive only the binding, so
  `Mfa\FactorCodeCallers` keeps MFA's caller beside it.
- `laravel-authentication`: `OneTimeCodeMessage` has no factor summary or purpose finer than `mfa`, so a sender cannot
  word a step-up's code differently.
- `laravel-mfa`: `PasskeyGateway::verifyAssertion()` is handed no client, so `verifyFactor()` gets an unknown one.
- `laravel-mfa`: `PendingSessionResolver::fromRequest()` is not handed the guard, so a pending caller is named after the
  default guard.
