# Codes, Delivery and Passkeys

## Purpose

This note describes how the package joins `laravel-authentication` and `laravel-mfa` for code challenges (IAM-3.9),
passkeys as factors (IAM-3.10) and the context MFA reads (IAM-3.12, the resolvers only), and how every member's codes
reach the application's own email and SMS gateways (IAM-3.13). It covers the seams `Mfa\MfaSeams`,
`Mfa\PasskeySeams`, `Mfa\ContextSeams` and `Delivery\DeliverySeams` add, what each adapter answers and how it
refuses, the one message both members' codes become, where each delivery runs and what a failing gateway undoes, and
the locks taken. The `mfa` context contributor comes later (M10) and is not described here; the seams joined in M2
are in `authentication-and-mfa.md`, and the binding rule that applies every row is in `binding-precedence.md`.

## Invariants

- Every row below is transient, replaces only its member's own default, and keeps a binding the application made
  before or after the members register (IAM-8.4). MFA's rows are on while `iam.adapters.mfa` is (read leniently, as in
  `authentication-and-mfa.md`); the passkey gateway row also needs an MFA application that offers the `passkey` type
  (`PasskeySeams::isOffered()`: any `mfa.applications.*.types` list holding `passkey`, read with each unregistered
  member's packaged configuration beneath the application's), while the passkey factor gate row needs only the switch
  (see below); the challenge gateway row also needs
  `laravel-authentication`'s path to be able to deliver MFA's codes (`DeliverySeams::routesFactorCodes()`, see
  Delivery); the delivery rows need their gateways (see below).

  | Member seam                | Adapter                       | Member default                | Table           |
  | -------------------------- | ----------------------------- | ----------------------------- | --------------- |
  | MFA `ChallengeGateway`     | `ChallengeGatewayAdapter`     | `PackageChallengeGateway`     | `MfaSeams`      |
  | AUTH `FactorCodeCounters`  | `FactorCodeCountersAdapter`   | `RefuseFactorCodes`           | `MfaSeams`      |
  | MFA `PasskeyGateway`       | `PasskeyGatewayAdapter`       | `UnavailablePasskeyGateway`   | `PasskeySeams`  |
  | AUTH `PasskeyFactorGate`   | `PasskeyFactorGateAdapter`    | `NoPasskeyFactors`            | `PasskeySeams`  |
  | MFA `EventContextResolver` | `EventContextResolverAdapter` | `DefaultEventContextResolver` | `ContextSeams`  |
  | MFA `ActiveTenantResolver` | `ActiveTenantResolverAdapter` | `NoActiveTenant`              | `ContextSeams`  |
  | MFA `SubjectTypeResolver`  | `SubjectTypeResolverAdapter`  | `IdentityContractSubjectType` | `ContextSeams`  |
  | MFA `ApplicationResolver`  | `ApplicationResolverAdapter`  | none (while unbound)          | `ContextSeams`  |
  | AUTH `OneTimeCodeSender`   | `OneTimeCodeSenderAdapter`    | none (while unbound)          | `DeliverySeams` |
  | MFA `SmsSender`            | `SmsSenderAdapter`            | `NullSmsSender`               | `DeliverySeams` |
  | MFA `EmailSender`          | `EmailSenderAdapter`          | `NullEmailSender`             | `DeliverySeams` |

- The passkey factor gate is the one mandatory row, and it is bound whenever MFA's switch is on, whether or not any
  application offers passkeys now: a passkey enrolled as a factor while the type was offered stays one after the
  application withdraws the type, and left on `NoPasskeyFactors`, its removal through `laravel-authentication` would
  leave its MFA factor and association standing (MFA has no listener for a removed passkey, and its boot check judges
  the passkey gateway only while the type is enabled). It changes nothing else while the type is not offered: a
  registration with no binding asks MFA nothing, MFA associates nothing for an application that does not enable
  passkeys, and MFA's `removing()` answers `null` after one plain read when the credential has no association. So a
  passkey that is still a factor is either removed with its factor or the removal is refused and rolls back. Only the
  passkey gateway, which runs MFA's ceremonies, waits for the type to be offered.
- Code challenges (IAM-3.9):
  - The challenge gateway adapter decides on every call which path a factor's code takes, against the container as it
    stands then: `laravel-authentication`'s factor codes only while its one-time code sender is bound and the factor is
    of MFA's own `sms` or `email` type, delivered by MFA's own `SmsDriver` or `EmailDriver` over this package's sender
    adapter of that channel (the sender the driver holds, not the one the container binds), so the code reaches the
    same gateway either way. Every other delivered factor's code is sent and checked by MFA's
    `PackageChallengeGateway`, built from the container, so the type's driver delivers it inside MFA's transaction, as
    MFA's contract asks: an `Mfa::extend()` override of `sms` or `email` (MFA's own driver built by hand over a sender
    of the application's among them), a type of the application's own of any channel kind (a WhatsApp, voice or push
    driver), MFA's own driver over a sender the application bound, before or after this package registers, and MFA's
    own driver registered under another type. A factor's sends and checks take the same path, since the choice
    depends on its type alone.
  - On `laravel-authentication`'s path, MFA's challenge gateway sends and checks the code through
    `laravel-authentication`'s factor codes (`Auth::codes()->sendFactorCode()` and `verifyFactorCode()`), under a
    `FactorCodeBinding` made from MFA's binding
    (`Mfa\Translation\CodeTranslator`): the identity is the factor's owner, which must be the identity the binding
    names; the channel is the factor's kind and destination; the enrolment grant is the pending factor's id, since
    MFA's own grant is a secret it never hands out.
  - `laravel-authentication`'s factor code counters ask MFA's `ChallengeCounters` inside `laravel-authentication`'s
    own transaction: `isUsable()` before each delivery or check, and `report()` once per counted attempt. The factor
    is found among the identity's own by its id; a binding whose channel kind or destination is not the factor's own
    is `not_found` without asking MFA, so no factor's code goes to another number or address.
  - Every `invalid` answer of `laravel-authentication`'s is MFA's counted `invalid_code`, never `replayed` or
    `not_found`: `laravel-authentication` answers a wrong code, a used challenge and an unknown one alike, and a
    refusal there would let a wrong code's count roll back, since MFA commits a counted failure and only a thrown
    refusal rolls back. Sends: `rate_limited` and `deliveries_exhausted` are `sending_capped` with the wait, `locked`
    is `locked`, a refusal keeps its reason. Checks: `expired` and `exhausted` are a refused `expired`, `locked` a
    refused `locked` with its end, `rate_limited` a refused `locked` until the wait ends, as MFA's own IP throttle
    answers. A `reauthenticate` binding is `not_accepted`.
  - A session key that is neither a string nor an integer, and an identity MFA holds no factors for, throw
    `UnresolvedReferenceException` inside `laravel-authentication`'s transaction, so nothing is kept.
- Passkeys as factors (IAM-3.10):
  - MFA's passkey gateway uses `laravel-authentication`'s factor ceremonies: `requestAssertion()` is
    `factorOptions()` under `laravel-authentication`'s binding of the same identity, application, session and purpose,
    returned as its `toArray()`; `verifyAssertion()` reads `challenge` and `credential` from the response
    (`PasskeyGatewayAdapter::CHALLENGE`, `CREDENTIAL`) and calls `verifyFactor()`. `passkey_challenge_invalid` is
    `expired`; every other failure (invalid credentials, a regressed counter, a malformed response, an empty
    allowlist, a credential outside it) is `invalid_code`. A binding naming another identity, or a request allowing
    none of the identity's passkeys, throws `OperationRefusedException(not_found)`.
  - `credentialIds()` lists the credential references of the identity's MFA passkey factors, read through MFA's `@api`
    `authFactors()` and `getCredentialReference()`, since `laravel-authentication` exposes no credential id
    (`PasskeySummary` leaves it out, by design). It stays meaningful because the gate below is mandatory: a passkey row
    and its factor are written and removed together. A factor whose passkey row is gone still cannot be asserted:
    `factorOptions()` finds nothing to allow, and the adapter refuses with `not_found`.
  - `laravel-authentication`'s passkey factor gate calls MFA's `PasskeyChangeGate` inside the passkey transaction. A
    registration with no binding returns `null`, so the key stays a sign-in passkey and MFA is never asked; one bound
    for another purpose than an enrolment is refused (`OperationRefusedException(not_found)`); an identity that is not
    MFA's is left alone on both paths. The registration's association is MFA's factor id, with MFA's whole
    `PasskeyAssociationResult` (summary, recovery codes, pending-session verification, and `laravel-authentication`'s
    `FactorChangeResult` on an active session) as its completion; a removal's completion is
    `laravel-authentication`'s `Sessions\FactorRemoval`, through the session revoker.
- Context (IAM-3.12, resolvers only), each reading `laravel-authentication`'s validated session through
  `Mfa\CurrentSession`, never `Auth::caller()` (which memoises the caller on the request), a request or an event:
  - the application is the default guard, as `Auth::shouldUse()` or the `auth` middleware leaves it, for guests,
    console and queue requests too, as MFA names it without a resolver; a blank default guard is unresolved;
  - the active tenant is the guard's validated session's recorded `tenant_id` when the guard serves the identity asked
    about, and `null` otherwise, never `Auth::tenant()`, a bind beside the session or a claim in the request; it runs
    no query. It does not throw for a missing session, because `laravel-authentication` asks MFA's requirement during
    sign-in, before the session row exists;
  - an event's context is MFA's allowlist: the identity's morph class and key, the application, the request's IP and
    user agent, and the principal, the session's tenant and the sign-in (`SignIn::reference()`) only when the guard
    holds a session of that identity; nothing of another identity's sign-in is attributed, and it never throws;
  - an identity is a person only when it is not `laravel-authentication`'s `MachineIdentity`, is MFA's
    `MultiFactorAuthenticatable` and can hold factors, so a machine counts as one whatever its model says.
  - Active state has no MFA seam: MFA reads `isMfaActive()` on the model, which its `HasFactors` answers `true`. The
    package ships `Concerns\MfaActiveFromAuthentication` (`@api`), whose `isMfaActive()` is
    `laravel-authentication`'s own `ActivationPolicy::isActive($this)`: `isActive()` of a `CanBeActive` model, run
    inside `WriteConnection::during()` so a check that reads the database is never answered by a lagging replica, and
    `true` for any other; an identity model uses it beside `HasFactors`, choosing its method with `insteadof`. MFA
    then refuses an identity `laravel-authentication` has deactivated as `identity_inactive` everywhere it asks (its
    challenge counters, so `laravel-authentication`'s factor code sends and checks, factor changes and removals), off
    request paths too, where no bearer token is refused first.
- Delivery (IAM-3.13):
  - The application implements `Contracts\EmailGateway` and `Contracts\SmsGateway` once each and names them in
    `iam.delivery.email` and `iam.delivery.sms` (or binds them). Each is given one `Delivery\CodeMessage`, whichever
    member issued the code: the application, this package's `Purpose` (`sign_in`, `verification`, `password_reset`,
    `identifier_change`, `additional_factor`, `enrollment`; the two members' `sign_in` never meet) and the member's
    own, the `Source`, the `Channel`, the member's type, the destination in its normal form, the code as
    `laravel-authentication`'s `Secret`, its expiry, the recipient and, for a code MFA sends itself, the factor's
    masked summary. The application words and lays out every message; the package composes no text.
  - `Delivery\DeliverySettings` resolves the gateway on every code: the application's binding of the contract wins,
    otherwise the class `iam.delivery.{channel}` names, which must implement it; anything else fails closed with
    `DeliveryNotConfiguredException`, which never names the code, the destination or the recipient, and which blames the
    key for a class it names that is no gateway and the container binding for one that resolves to what is no gateway
    of the channel (`forBinding()`), so an empty key is never named as the fault.
  - A code of `laravel-authentication`'s goes out on the channel `iam.delivery.types` maps its identifier type to
    (shipped `['email' => 'email', 'phone' => 'sms']`, read in full when the application's `delivery` block leaves it
    out), except a further factor's or an enrolment's (purpose `mfa` or `enrollment`), whose type is its factor's
    channel kind (`sms`, `email`) and which goes out on that channel. A code of MFA's own `sms` or `email` type the
    challenge gateway adapter sends on that path takes that route, naming no factor and no finer purpose than `mfa`;
    its type is then the factor's own.
  - Binding: each MFA sender is pointed at its gateway once that gateway is named or bound when this package
    registers; the one-time code sender once every gateway the routes reach is. Unnamed, nothing is bound (IAM-1.3):
    MFA keeps its Null senders, which its boot check refuses while an application offers `sms` or `email`, and
    `laravel-authentication` keeps its sender unbound.
  - The challenge gateway adapter is bound while `laravel-authentication`'s path can deliver MFA's codes: its
    one-time code sender is bound, the application's or this package's (`DeliverySeams::routesFactorCodes()`).
    Otherwise MFA keeps `PackageChallengeGateway` and delivers its codes through its own senders. Who binds MFA's
    senders, and when, is never read there: the adapter judges each code as it is sent (see Code challenges), so an
    MFA sender or driver the application binds or registers, before this package registers or after, in a provider's
    `register()` or `boot()`, whatever order the providers register in, is the one its codes go through (IAM-8.4).
    Either way the senders MFA's boot check judges are the ones its codes go through: on `laravel-authentication`'s
    path a factor's code goes out through the gateway of its channel, which is available exactly while MFA's sender of
    that channel is pointed at it; on MFA's own path the senders and drivers deliver them. So a type an application
    offers whose gateway is missing refuses boot, and an application's own MFA sender or delivered driver is the one
    used, never silently bypassed.
  - Where each delivery runs differs by member, and this package never queues one itself:
    - a code MFA sends itself is delivered synchronously inside MFA's transaction, after its identity state and
      factor locks and its code row, taking no lock; a gateway that throws (or one that cannot be resolved) is
      rethrown as MFA's `CodeDeliveryFailedException` and rolls the code back with what it was for;
    - every code `laravel-authentication` issues, an MFA factor code sent through it included, is delivered from its
      queued `SendOneTimeCode` job, pushed once the outermost transaction commits, outside any transaction; a gateway
      that throws fails the job, the code stays issued and unused, and the queue's retry checks it is still current
      and delivers it. MFA has already reported the code sent.
  - A gateway that queues its own delivery must reveal what it needs into a job whose whole payload is encrypted
    (`ShouldBeEncrypted`), since the message refuses to be serialised, and MFA then reports the code sent at enqueue.
  - The message refuses to be serialised or unserialised, its code refuses to be cast or encoded, and a dump shows
    neither code, destination nor recipient. Logged by accident, MFA's log redaction logs it by its public properties
    with the code redacted under its key; it is not `JsonSerializable`, so the redaction never asks it for a form it
    would refuse, and the log is written instead of failing the delivery.
  - The package ships contract kits for the gateways (`Testing\Seams\EmailGatewayContract`, `SmsGatewayContract`,
    and the `EmailGatewayTests` and `SmsGatewayTests` traits): every purpose of both members delivered once, neither
    the code nor the destination in any log entry, its context or a failure's exception chain, traces included, and a
    failure that throws and delivers nothing. `Testing\FakeEmailGateway` and `FakeSmsGateway` pass them.
  - The kits read the log through `Testing\Seams\LogRecorder`, from Laravel's `MessageLogged` event, as the log's
    formatters write it: an exception, and each previous one, by its type, code, message, file and line and its stack
    trace (Laravel's channels write the trace of every logged exception), then its JSON form when it gives one, as
    Monolog's normaliser writes it; a `JsonSerializable` by its JSON form, a `Stringable` by its string, an enum by
    its value, any other object by its public properties (and by them too when it refuses the first two, as a
    `Secret` does, as Monolog falls back), an object met again inside itself by its type. The exception a failed
    delivery throws is read the same way, as the worker's exception handler reports it, and fails the check when it
    holds anything nested deeper than the kit reads. A context nested deeper than 16 levels is never taken as clean:
    it fails the check. Before each call the recorder dispatches an entry of its own through the default channel's
    event dispatcher, and fails unless it reached its listener, so a test case that fakes `MessageLogged`
    (`Event::fake()`) fails the logging checks rather than pass them unseen.
  - Traces are read with every argument whole. A trace's frames hold their string arguments (up to 15 characters by
    default, enough for a whole code or a whole E.164 number) unless `zend.exception_ignore_args` is on, and PHP cuts
    them to `zend.exception_string_param_max_len` when it writes the trace, so a gateway that hands the destination or
    the code to a provider's client whose exception it logs or rethrows writes both to the log. While the call runs,
    and while the exception it threw is read, the recorder turns `zend.exception_ignore_args` off and sets
    `zend.exception_string_param_max_len` to its maximum, so the check sees what a trace could hold wherever the
    gateway runs, whatever the test's `php.ini` says, and puts both back afterwards. A gateway passes by keeping the
    message out of the arguments of any call whose exception it logs or throws, or by marking those parameters
    `#[\SensitiveParameter]`, which PHP leaves out of every trace.
  - The two contracts share `Testing\Seams\GatewayContract`, and the two traits share `Concerns\GatewayTests`. Each
    contract checks only its own channel's gateways, so it fails a gateway of the other channel before it sends
    anything. A test case proves one gateway, and implements the hooks `codeGateway()`, `codeApplication()` (the guard
    the gateway serves, which every message the kit sends is for, so a gateway that picks its template, brand or
    sender by the application and refuses one it does not serve passes as it runs), `codeRecipient()`,
    `codesDeliveredTo()` and `failCodeDelivery()`; the contracts take the application beside the gateway and the
    recipient. `GatewayAssert::APPLICATION` is only the application this package's own fakes are proved for. MFA's two
    senders share `Delivery\MfaSenderAdapter`.
- Lock order:
  - a challenge MFA starts or checks takes MFA's identity state, then its factors, then `laravel-authentication`'s
    session row (the first factor MFA's combination policy reads), then the `rate_limits` rows of its code limits,
    then the `one_time_codes` row. Every such path holds the identity state first, so no two of them deadlock. The
    `code_request` and `factor_code` limit rows are written inside MFA's transaction and roll back with it, and they
    serialise MFA code requests from one IP address or to one destination until it commits; MFA's own IP throttle
    counts the same request too;
  - a passkey registration or removal takes MFA's identity state and factors (and the session row, for a session
    transition or a revocation) before the passkey row is inserted or deleted, in `laravel-authentication`'s passkey
    transaction, as both members' contracts ask.

## Success Path

- Name both gateways (`iam.delivery.email`, `iam.delivery.sms`) and offer `sms` and `email` as MFA types. An enrolment
  started through `Mfa::startEnrollment()` issues its code through `laravel-authentication`; the queued job delivers
  it through the gateway of the factor's channel as a `CodeMessage` from `authentication` for `enrollment`, and
  `Mfa::confirmEnrollment()` confirms it. A step-up through `Mfa::sendCode()` and `Mfa::verify()` arrives the same way
  as an `additional_factor` code and is recorded on the session with the factor. MFA's events about both carry the
  tenant the validated session records.
- A one-time code sign-in (`email_code`, `phone_code`) asked for through `Auth::codes()->send()` reaches the gateway
  its identifier type routes to as a `sign_in` message, in the identifier's normal form, and signs the person in.
- A passkey registered through `laravel-authentication` with an enrolment binding becomes a confirmed passkey factor,
  steps the session up through `Mfa::requestAssertion()` and `Mfa::verify()`, and, removed through
  `laravel-authentication` on a step-up with another factor, takes its factor and association with it. Removed as a
  factor through `Mfa::removeFactor()` instead, it stays a sign-in passkey with no factor behind it, and its later
  removal asks MFA nothing. Once the application withdraws the `passkey` type, no ceremony runs, but removing a
  passkey that is still a factor still takes its factor and association with it, or is refused and rolls back whole.

## Failure / Edge Cases

- The rule that a gateway which throws rolls the issued code back holds only for codes MFA sends itself.
  `laravel-authentication` commits its code before its job delivers it, so a failing gateway leaves the code issued
  and retried; MFA factor codes routed through it behave the same, and MFA reports them sent before delivery.
- `laravel-authentication` answers a used, unknown or malformed challenge `invalid`, as a wrong code, so the adapter
  answers each as a counted `invalid_code`. MFA's `ChallengeGatewayTests` checks of `replayed` and `not_found` are
  skipped with the gap named; this package's own tests pin what is answered instead.
- `ChallengeCounters::report()` never says that the failure it counted locked the factor, so the counters adapter
  answers `admitted` for that failure and the next admission finds the lock.
- An application that names one gateway only gets MFA's sender of that channel, and no one-time code sender while the
  routes reach the other; binding that sender changes `laravel-authentication`'s `bound()` checks (password resets,
  identifier changes, its configuration check). MFA then keeps its own challenge gateway, so the codes of the named
  channel's factors arrive through MFA's sender, inside MFA's transaction, and the other channel's type, offered,
  refuses boot. Routes that are empty or name an unknown gateway leave MFA on its own challenges the same way.
- The switches read the container when this package registers: a one-time code sender or a gateway the application
  binds later (a later `register()`, any `boot()`) binds nothing of this package's, so the application names the
  gateways, or binds before this package registers, instead. An MFA sender or delivered driver is never read there:
  the challenge gateway adapter judges it as each code is sent, so one bound or registered later is still the one
  used.
- MFA exposes neither whether a type's driver is the one it ships nor the sender a shipped driver holds, so the
  adapter reads the driver's class and, by reflection, the private `sender` its `SmsDriver` or `EmailDriver` was built
  with (member gap: a public accessor would remove the reflection). An application that registers MFA's own driver by
  hand through `Mfa::extend()` over a sender of its own therefore has the type's codes delivered by that sender,
  inside MFA's transaction, as it does when it binds the sender.
- A code whose type routes nowhere, or whose gateway is neither bound nor named, fails closed with
  `DeliveryNotConfiguredException`: inside MFA's transaction for MFA's own codes, in the job for
  `laravel-authentication`'s.
- A passkey removal goes through MFA's change gate, which acts only for the request's validated caller with a fresh
  step-up, so an administrator's, a console's or a queued removal of another identity's passkey factor is refused
  (`not_found` or `not_fresh`) and rolls back; a removal on a step-up made only with the passkey itself is refused by
  `laravel-authentication` (`step_up_required`).
- `verifyFactor()` reports an unknown, used or expired challenge alike, so all are `expired`, never `replayed`.
- With the application resolver bound, MFA's `ProofService::applicationFor()` ignores its guard argument, so a `Login`
  or `Logout` on a guard other than the default is named after the default guard; harmless while the proof store's
  `begin()` and `forget()` do nothing (M2), and a later store that keys on the application must allow for it.

## Implementation Anchors

- `src/Mfa/MfaSeams.php` (`seams()`, `isOn()`), `src/Mfa/PasskeySeams.php` (`seams()`, `isOffered()`, `TYPE`),
  `src/Mfa/ContextSeams.php`, `src/Delivery/DeliverySeams.php` (`routesFactorCodes()`, `isAvailable()`, `isNamed()`,
  `contract()`, `DEFAULT_TYPES`); `src/IamServiceProvider.php`: `seamProviders()`; `config/iam.php`: `adapters.mfa`,
  `delivery`.
- `src/Mfa/ChallengeGatewayAdapter.php` (`routedKind()`, `isPointedAtGateway()`, `mfasOwn()`),
  `src/Mfa/FactorCodeCountersAdapter.php`, `src/Mfa/Translation/CodeTranslator.php`.
- `src/Mfa/PasskeyGatewayAdapter.php` (`CHALLENGE`, `CREDENTIAL`, `reason()`), `src/Mfa/PasskeyFactorGateAdapter.php`.
- `src/Mfa/EventContextResolverAdapter.php`, `src/Mfa/ActiveTenantResolverAdapter.php`,
  `src/Mfa/SubjectTypeResolverAdapter.php`, `src/Mfa/ApplicationResolverAdapter.php`,
  `src/Concerns/MfaActiveFromAuthentication.php`.
- `src/Contracts/EmailGateway.php`, `src/Contracts/SmsGateway.php`, `src/Delivery/CodeMessage.php`
  (`fromAuthentication()`, `fromMfa()`), `src/Delivery/Enums/Purpose.php`, `Channel.php`, `Source.php`,
  `src/Delivery/DeliverySettings.php` (`gateway()`, `channelFor()`), `src/Delivery/OneTimeCodeSenderAdapter.php`,
  `MfaSenderAdapter.php`, `SmsSenderAdapter.php`, `EmailSenderAdapter.php`,
  `src/Exceptions/DeliveryNotConfiguredException.php`.
- `src/Testing/FakeEmailGateway.php`, `src/Testing/FakeSmsGateway.php`, `src/Testing/Seams/GatewayContract.php`,
  `EmailGatewayContract.php`, `SmsGatewayContract.php`, `GatewayAssert.php`, `LogRecorder.php` (`UNREAD`,
  `UNREADABLE`), `src/Testing/Seams/Concerns/GatewayTests.php`,
  `EmailGatewayTests.php`, `SmsGatewayTests.php`.

## Authoritative Tests

- `tests/Integration/EndToEnd/DeliveredFactorsTest.php`
  `testADeliveredFactorIsEnrolledChallengedAndVerifiedThroughTheGateway`,
  `testMfasEventsCarryTheTenantOfTheCallersSession`, `testAFailedDeliveryLeavesTheCodeIssuedForTheQueuesRetry`,
  `testWithMfasOwnChallengesAFailedDeliveryRollsTheCodeBack` (an SMS and an email factor, on MySQL and PostgreSQL at
  READ COMMITTED and REPEATABLE READ)
- `tests/Integration/EndToEnd/CodeSignInTest.php` `testACodeSignInIsDeliveredThroughTheGatewayItsTypeRoutesTo`,
  `testAFailedDeliveryLeavesTheCodeIssuedForTheQueuesRetry`
- `tests/Integration/EndToEnd/PasskeyFactorsTest.php` `testAPasskeyRemovedThroughAuthenticationTakesItsFactorWithIt`,
  `testAPasskeyFactorRemovedThroughMfaLeavesOnlyASignInPasskey`
- `tests/Integration/EndToEnd/WithdrawnPasskeyFactorsTest.php`
  `testAPasskeyFactorLeftByAWithdrawnTypeIsRemovedWithItsPasskey`,
  `testAPasskeyFactorLeftByAWithdrawnTypeIsRemovedWithItsPasskeyAtEachLevel`,
  `testARefusedRemovalKeepsThePasskeyAndItsFactor`, `testARefusedRemovalKeepsThePasskeyAndItsFactorAtEachLevel`
- `tests/Feature/Mfa/MfaSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`;
  `tests/Feature/Mfa/PasskeySeamsTest.php` `testBothAdaptersAreBoundWhilePasskeysAreOfferedInEveryProviderOrder`,
  `testOnlyTheGateIsBoundWhileNoApplicationOffersPasskeys`,
  `testTheGatewayIsOnWhilePasskeysAreOfferedAndTheGateWhileMfaIs`,
  `testBothBindingsAreTransientAndTheGateIsMandatory`;
  `tests/Feature/Mfa/ContextSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testTheSwitchOffBindsNothing`; `tests/Feature/Delivery/DeliverySeamsTest.php`
  `testNothingIsBoundWhileNoGatewayIsNamed`, `testTheOneTimeCodeSenderIsBoundOnceEveryRoutedGatewayIsNamed`,
  `testAGatewayBoundBeforeAnyProviderRegistersCountsAsNamed`, `testWithOneGatewayNamedMfaSendsThatChannelsCodesItself`,
  `testAConfigurationThatCannotDeliverAnOfferedTypeIsRefusedAtBoot`,
  `testFactorCodesAreRoutedOnlyWhileAuthenticationDeliversThem`; `tests/Feature/Mfa/MfaSeamsTest.php`
  `testMfaKeepsItsOwnChallengesWhileAuthenticationWouldNotDeliverThem`,
  `testAnApplicationsOwnMfaSenderBindsAlikeWheneverItIsBound`, `testAnApplicationsOwnOneTimeCodeSenderRoutesMfasCodes`,
  `testTheChallengeGatewaysSwitchReadsWhetherAuthenticationCanDeliver`; `tests/Feature/Delivery/DeliverySeamsTest.php`
  `testAnApplicationSenderBoundBeforeAnyProviderRegistersIsKept`,
  `testAnApplicationSenderBoundOnceEveryProviderHasRegisteredWins`;
  `tests/Integration/EndToEnd/OneGatewayFactorsTest.php` `testAFactorOfTheOneGatewaysChannelIsDeliveredThroughIt`
- Code challenges: `tests/Integration/Mfa/ChallengeGatewayAdapterTest.php` (over MFA's `ChallengeGatewayTests`)
  `testACodeIsSentThroughAuthentication`, `testAStepUpIsProvedWithACodeThroughAuthentication`,
  `testAnEnrolmentIsConfirmedWithACodeThroughAuthentication`, `testAUsedCodeNeverAnswersAgain`,
  `testAnUnknownChallengeNeverPasses`, `testACodeAskedForAgainTooSoonIsSendingCapped`,
  `testChecksBeyondTheIpAddresssLimitAreRefusedAsLocked`, `testAReauthenticationIsNotAccepted`,
  `testACheckInsideTheCallersTransactionRollsBackWithIt`; `tests/Integration/Mfa/ChallengeGatewayRoutingTest.php`
  `testAnApplicationsDriverOfAShippedTypeDeliversItsCodes`,
  `testAnApplicationsDriverDeliversInsideMfasTransactionAtEachLevel`,
  `testATypeOfTheApplicationsOwnOfAnotherChannelKindIsDeliveredByItsDriver`,
  `testMfasDriverOverASenderTheApplicationBindsDeliversThroughThatSender`,
  `testMfasDriverExtendedOverASenderOfTheApplicationsOwnDeliversThroughThatSender`,
  `testMfasDriverUnderAnotherTypeReachesTheGatewayAsThatType`, `testWithNoOneTimeCodeSenderBoundMfaSendsItsCodesItself`,
  `testAShippedTypeWithMfasDriverGoesThroughAuthentication`;
  `tests/Integration/Delivery/ApplicationMfaSenderTest.php`
  `testAnApplicationsSenderReceivesItsChannelsCodesWheneverItIsBound`;
  `tests/Integration/Mfa/FactorCodeCountersAdapterTest.php`
  (over MFA's `ChallengeCountersTests`) `testABindingOnAnotherChannelThanTheFactorsIsNotFound`,
  `testAnUnresolvableSessionThrowsInsideAuthenticationsTransaction`,
  `testAWrongCodeThatReachesTheFactorsLimitLocksIt`, `testADeactivatedIdentitysFactorCodesAreRefusedAsInactive`;
  `tests/Unit/Concerns/MfaActiveFromAuthenticationTest.php`
  `testAnIdentityIsActiveToMfaWhileAuthenticationReadsItActive`, `testAnIdentityIsActiveToMfaAsThePrimaryHasIt`;
  `tests/Unit/Mfa/Translation/CodeTranslatorTest.php`
  `testEveryCheckCrossesAsMfasOutcome`, `testARefusedRequestCrossesAsMfasRefusal`
- Lock order: `tests/Integration/Mfa/CodeChallengeLockOrderTest.php`
  `testAChallengeLocksTheIdentityTheFactorsTheSessionTheCountsThenTheChallenge`;
  `tests/Integration/Mfa/PasskeyFactorGateAdapterTest.php` `testMfasLocksComeBeforeThePasskeysRow`;
  `tests/Integration/Delivery/MfaCodeDeliveryTest.php` `testTheGatewayRunsInsideMfasTransactionAndTakesNoLock`
- Passkeys: `tests/Integration/Mfa/PasskeyGatewayAdapterTest.php` (over MFA's `PasskeyGatewayTests`)
  `testAPasskeyFactorStepsTheSessionUpThroughMfa`, `testTheRegisteredPasskeysAreThePasskeyFactors`,
  `testARequestAllowingNoneOfTheIdentitysPasskeysIsRefused`, `testEachFailureReasonCrosses`;
  `tests/Integration/Mfa/PasskeyFactorGateAdapterTest.php` (over MFA's `PasskeyChangeGateTests`)
  `testAnEnrolmentRegistrationBecomesAFactor`, `testARegistrationWithoutABindingStaysASignInPasskey`,
  `testARegistrationBoundForAnotherPurposeIsRefused`, `testRemovingAPasskeyNeverLeavesItsFactorStanding`,
  `testARemovalMfaRefusesKeepsThePasskeyAndItsFactor`
- Context: `tests/Integration/Mfa/EventContextResolverAdapterTest.php` (over MFA's `EventContextResolverTests`)
  `testAnEventAboutTheServedIdentityCarriesItsSignIn`, `testNothingOfAnotherIdentitysSignInIsAttributed`,
  `testNoTenantSetBesideTheSessionIsCarried`; `tests/Integration/Mfa/ActiveTenantResolverAdapterTest.php`
  `testTheTenantIsTheOneTheSessionRecords`, `testNoTenantClaimedBesideTheSessionIsEverTheActiveOne`,
  `testASignInJudgedBeforeItsSessionIsWrittenSignsIn`, `testInsideATransactionItRunsNoQuery`;
  `tests/Integration/Mfa/SubjectTypeResolverAdapterTest.php` (over MFA's `SubjectTypeResolverTests`)
  `testAMachineIsNoPersonWhateverItsModelSays`; `tests/Integration/Mfa/ApplicationResolverAdapterTest.php` (over
  MFA's `ApplicationResolverTests`) `testTheApplicationIsTheGuardThatServesTheRequest`,
  `testASignedInRequestAndAGuestsAreNamedAlike`
- Delivery: `tests/Integration/Delivery/MfaCodeDeliveryTest.php` `testAGatewayThatThrowsRollsTheCodeBack`,
  `testAGatewayTheAdapterCannotResolveRollsTheCodeBack`; `tests/Integration/Delivery/AuthenticationCodeDeliveryTest.php`
  `testAGatewayThatThrowsFailsTheDeliveryJob`, `testAFactorCodeReachesTheGatewayOfItsChannel`,
  `testACodeThatRoutesNowhereFailsTheDeliveryJob`; `tests/Unit/Delivery/DeliverySettingsTest.php`
  `testTheApplicationsBindingWinsOverTheClassItNames`, `testAGatewayNeitherBoundNorNamedFailsClosed`,
  `testABindingThatIsNoGatewayOfItsChannelFailsClosed`, `testANamedGatewayBoundToWhatIsNoGatewayOfItsChannelFailsClosed`,
  `testACodeGoesOutOnTheChannelItRoutesTo`, `testACodeThatRoutesNowhereFailsClosed`
- The message: `tests/Unit/Delivery/CodeMessageTest.php` `testThePurposeFollowsAnAuthenticationPurpose`,
  `testThePurposeFollowsAnMfaPurpose`, `testADumpShowsNeitherTheCodeTheDestinationNorTheRecipient`,
  `testAMessageRefusesToBeSerialised`; `tests/Feature/Delivery/CodeMessageLoggingTest.php`
  `testALoggedMessageIsWrittenWithItsCodeRedacted`
- The kits: `tests/Feature/Testing/FakeEmailGatewayTest.php` and `tests/Feature/Testing/FakeSmsGatewayTest.php`
  `testGatewayDeliversEveryPurposeOnce`, `testGatewayLogsNothingOfTheMessage`, `testGatewayThrowsWhenDeliveryFails`;
  `tests/Feature/Testing/GatewayAssertTest.php` `testAGatewayThatDeliversTwiceFails`,
  `testAGatewayThatLogsTheMessageFails`, `testAGatewayThatFailsBadlyFails`,
  `testAGatewayOfTheOtherChannelFailsTheContract`, `testAGatewayThatLogsTooDeepFails`,
  `testTheLoggingChecksFailWhileEventsAreFaked`, `testTheMessagesCoverEveryPurposeOfBothMembers`;
  `tests/Feature/Testing/GuardScopedGatewayTest.php` `testEveryMessageIsForTheGuardTheTestCaseNames`;
  `tests/Feature/Testing/LogRecorderTest.php`
  `testAnExceptionIsReadAsTheLogWritesIt`, `testATraceHoldsEveryArgumentWholeWhileTheCallRuns`,
  `testAThrownExceptionIsReadToTheDepthTheKitReads`,
  `testAnObjectIsReadAsTheLogWritesIt`, `testAContextNestedTooDeepIsReadAsUnread`,
  `testTheRecorderFailsWhenItCannotReadTheLog`

## Change Triggers

Update this note when:

- a member renames, adds or removes one of the seams in the table, or changes a default's class or binding style;
- `laravel-authentication` tells a used or unknown challenge from a wrong code in `FactorCodeCheck`, or a used passkey
  challenge from an expired one (the adapters could answer `replayed` and `not_found`, and the kit's skipped checks
  would run);
- `laravel-authentication` delivers factor codes inside their transaction, or gains an opt-in to do so (a failing
  gateway would then roll every code back), or stops queueing its deliveries;
- `laravel-authentication` gains a public read of an identity's passkey credential ids, or MFA passes the
  application to `PasskeyGateway::credentialIds()` (the gateway would read them from `laravel-authentication`);
- MFA gains a seam for active state, a rate-limited failure reason, a lockout caused by a reported failure, or an
  application argument to its application resolver;
- MFA's `CodeMessage`, `laravel-authentication`'s `OneTimeCodeMessage`, or either member's purposes change (the
  neutral message and its purposes follow them);
- MFA's log redaction changes how it logs an object, Monolog's normaliser or line formatter changes how it writes one
  or an exception, or PHP changes what a stack trace records of a frame's arguments (the kit's `LogRecorder` reads
  objects, exceptions and traces as they do), or either member changes the lock order of a challenge or a passkey
  change;
- MFA's `HasFactors` reads active state itself, or MFA's boot check stops judging its senders (the challenge gateway's
  switch relies on it);
- MFA exposes whether a type's driver is its own, or the sender a shipped driver holds (the adapter could stop
  reflecting on the driver's private `sender`); or MFA's `SmsDriver` or `EmailDriver` stops being final, renames or
  drops its `sender` property, or `PackageChallengeGateway` stops delivering through the type's driver (the challenge
  gateway adapter's choice of path relies on all three);
- the `mfa` context contributor lands (M10), or a proof store keys on the application.
