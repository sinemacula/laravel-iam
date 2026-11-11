<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The one database connection every member's tables live on, `null` for the
    | default connection. It is written into
    | `authentication.storage.connection`, `mfa.storage.connection` and
    | `sso.storage.connection` wherever a member leaves its own key unset, so a
    | change that spans members runs in one transaction; a member key that names
    | another connection refuses boot. Keep it fixed while the application runs:
    | moving the tables is a deploy, with a migration the application performs
    | and a worker restart.
    |
    */

    'storage' => [
        'connection' => env('IAM_STORAGE_CONNECTION'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Adapters
    |---------------------------------------------------------------------------
    |
    | Which members this package binds together. `mfa` binds
    | `laravel-authentication` and MFA through each other's seams: the
    | additional-factor requirement and the requirement check, pending sessions,
    | step-up, reauthentication and freshness, factor changes, revocation on
    | factor removal and reset, the return to pending, the proof store, the
    | first factor, the recorder of MFA's verified test sign-ins, code
    | challenges and their counters, the event context, the active tenant, the
    | subject type, the active state and the application, the passkey factor
    | gate, while any MFA application offers the `passkey`
    | factor type, MFA's passkey ceremonies, and the `mfa` namespace of the
    | authentication context. Each adapter replaces only the member's own
    | default, never a binding of the application's, and a contributor the
    | application registers under `mfa` is kept. Turn it off (`false`, `0`,
    | `off`, `no`) only to bind every one of those seams yourself, and register
    | an `mfa` contributor of your own: revocation on factor removal is
    | mandatory, as is the passkey factor gate, even once passkeys are no
    | longer a factor type, and the members' defaults leave both undone. A
    | value it does not recognise leaves it on.
    |
    | `sso` binds `laravel-authentication` and SSO: SSO's re-authentication
    | sessions, answered from `laravel-authentication`'s sessions; its session
    | revocation, ending `laravel-authentication`'s sessions inside SSO's own
    | change; `laravel-authentication`'s external identity links, answered from
    | the redemption SSO admitted in the request alone; SSO's own link store as
    | its linker and link storage; `laravel-authentication`'s external evidence
    | policy, answered from the evidence SSO accepted with MFA's combination
    | policy as the second gate; SSO's freshness, application policy and link
    | email matcher, answered by `laravel-authentication`'s freshness policy,
    | sign-in methods and email normaliser; SSO's link confirmation, answered
    | from how the caller's session signed in (a password, a passkey or the
    | application's own recovery); while `sso.evidence` is on, SSO's
    | per-connection evidence policy; and the `sso` namespace of the
    | authentication context. SSO's freshness judges only the caller SSO is
    | handed: pass a call into SSO that asks it (a management helper, a link
    | flow's start) `Iam::callers()->of($caller)`, `$caller` being
    | `laravel-authentication`'s `Caller` (`Auth::caller()`); without one it is
    | stale. SSO keeps its own handoff codes either way. Turn it off (`false`,
    | `0`, `off`, `no`) only to bind every one of those seams yourself:
    | revocation is mandatory, since SSO's default leaves every session
    | standing when a tenant's enforcement changes, a connection is disabled or
    | deleted, a link is removed or a scope widened, and
    | `laravel-authentication`'s default links nothing, so no SSO sign-in
    | succeeds. A value it does not recognise leaves it on.
    |
    | While `sso` is on, the package also binds `laravel-authentication`'s
    | tenant authentication policy, answered from SSO's enforcement, SSO's
    | exemptions and MFA's tenant requirement together, whatever `mfa` says:
    | it finds the connection of a sign-in through the redemption this
    | package's SSO capability admitted, which nothing records with `sso` off.
    | With `sso` off, bind it yourself: it is mandatory while
    | `sso.features.enforcement` is on or MFA's tenant requirement is bound,
    | since `laravel-authentication`'s default requires nothing of any
    | tenant, so no enforcement and no requirement would reach a session.
    |
    | While `sso` is on and the application names its memberships
    | (`tenancy.memberships`), the package binds SSO's tenant membership, its
    | link eligibility and its principal scope, answered from them. Without
    | them SSO's defaults stay, and refuse. While `sso` is on, SSO's
    | enforcement inheritance reads `laravel-authorization`'s tenant tree.
    |
    | `authorization` binds `laravel-authorization` to the other members: its
    | subject resolver, answered from `Auth::caller()` (the principal, its
    | identity, the active tenant, the application and the session); its
    | authentication context, `laravel-authentication`'s, with the `mfa` and
    | `sso` namespaces, whose keys it declares to its key catalogue; while
    | `mfa` is on too, its requirement checker, answered by MFA's requirement
    | check on the session's own proofs, and its insufficient-authentication
    | exception, rendered as MFA's step-up; its session policy source,
    | answered from the caller's credential scopes; and
    | `laravel-authentication`'s scope registry and application access,
    | answered from it. Each adapter replaces only the member's own default,
    | never a binding of the application's nor a class the application names
    | in `laravel-authorization`'s configuration. Turn it off (`false`, `0`,
    | `off`, `no`) only to bind those seams yourself: `laravel-authorization`'s
    | defaults know no `jwt` guard's session, tenant or scopes, so no tenant's
    | grant counts and every authentication requirement is unmet. A machine is
    | then capped by nothing, its credential's scopes ignored, unless it
    | implements `laravel-authorization`'s `AuthorizableMachine`, which is
    | allowed nothing, so while a guard accepts `api_key` or
    | `client_credentials`, `iam:check` refuses that default session policy
    | source, as it refuses `laravel-authentication`'s default scope registry,
    | whatever this switch says. A value it does not recognise leaves it on.
    |
    */

    'adapters' => [
        'mfa'           => env('IAM_ADAPTERS_MFA', true),
        'sso'           => env('IAM_ADAPTERS_SSO', true),
        'authorization' => env('IAM_ADAPTERS_AUTHORIZATION', true),
    ],

    /*
    |---------------------------------------------------------------------------
    | Tenancy
    |---------------------------------------------------------------------------
    |
    | Which further factors a tenant requires is the application's own data:
    | implement laravel-mfa's `TenantRequirement` and bind it. MFA asks it
    | itself, and while `adapters.sso` is on the package reads it, on the write
    | connection, into `laravel-authentication`'s tenant authentication policy,
    | with SSO's enforcement and exemptions, at a version that changes when any
    | of them does. An identity that is not `MultiFactorAuthenticatable` is
    | refused once one is bound. Leave MFA's default and no tenant requires a
    | further factor.
    |
    | Whenever a tenant's answer changes, report it so the sessions that no
    | longer meet it end: call `Iam::tenantPolicies()->changed($tenant)`
    | inside the transaction that publishes the change, on the storage
    | connection (`Iam::transaction()` opens one). It judges the tenant's
    | sessions there, so both commit or roll back together, and once more
    | after that transaction commits, the strict cut-off
    | `laravel-authentication`'s `tenantPolicyChanged()` asks for: a session
    | that entered the tenant while the first pass ran, having read the old
    | answer, is judged only by the second. Calling
    | `Auth::sessions()->tenantPolicyChanged($tenant)` yourself, call it twice
    | the same way, once inside that transaction and once after it commits.
    | Report the same whenever the answer of SSO's `EnforcementExemption`
    | changes for an identity, a grant or a withdrawal: for every tenant whose
    | enforcement the identity was, or is now, exempted from. Nothing else
    | starts that judgement (SSO revokes only for a change of its own rules),
    | and bearer requests never recheck the tenant's policy, so a withdrawn
    | exemption's sessions would otherwise keep acting in the tenant on their
    | access tokens until those expire.
    |
    | `memberships` names the application's memberships, a class implementing
    | `SineMacula\Laravel\Iam\Contracts\Memberships`: every tenant an
    | identity is a current member of, a platform principal among them, and
    | when the person, never an administrator, accepted each, or the set marked
    | incomplete when it cannot all be read. While `adapters.sso` is on, the
    | package answers SSO's tenant membership, its link eligibility (a `link`
    | only by an accepted membership of the connection's tenant) and the
    | membership half of its principal scope from it. The grant half is
    | `laravel-authorization`'s grant scope query while `adapters.authorization`
    | is on, so the principal scope is `within_tenant` only for a person whose
    | memberships and grants both stay within the tenant, and `unknown` with it
    | off, so SSO links nobody by a verified domain; a complete set reaching
    | beyond the tenant is `outside_tenant`, which suspends a verified domain
    | link for good. Name none and SSO's defaults stay: no membership, no
    | `link`, no linking by a domain.
    |
    | The tenant tree is `laravel-authorization`'s (`authorization.tenant_tree`).
    | Report every move of a tenant inside the transaction that writes it,
    | after the write: `Iam::treeChanges()->changed($tenantId)`.
    |
    | Memberships bound in the container count as named when they are bound
    | by the time every service provider has registered (in a provider's
    | `register()`, the application's own included); bound from a provider's
    | `boot()` they are still the ones asked, but bind no adapter. Any
    | value that is no class name (true, false, a number) fails closed.
    |
    */

    'tenancy' => [
        'memberships' => null,
    ],

    /*
    |---------------------------------------------------------------------------
    | Provisioning
    |---------------------------------------------------------------------------
    |
    | `provisioner` names the application's provisioner, a class implementing
    | `SineMacula\Laravel\Iam\Contracts\Provisioner`: what a person who signs
    | in through an SSO connection for the first time is made into, a new
    | identity and its membership of the connection's tenant. A provisioner
    | bound in the container counts as named, whenever it is bound. Name none
    | (leave it null) and provisioning is off: a `sign_in` that resolves to no
    | identity ends as SSO's `unlinked`. Any value that is no class name (true,
    | false, a number) fails closed.
    |
    | The package's one listener of SSO's `ResultUnlinked` asks it, only for a
    | result that resolved to no identity and holds no reservation, never for
    | `laravel-authentication`'s informational `ExternalResultUnlinked`. In
    | one transaction on the storage connection, attempted once, it creates
    | the identity (always a new one, inserted then, never one found by an
    | email address or any other attribute), reports the new principal
    | through SSO's scope widening, creates the membership, and links the
    | result to the identity through SSO's provisioning helper. A refusal from
    | the helper, or anything thrown, rolls all three back; once it commits,
    | they stay made even if the sign-in then fails, and the next sign-in
    | resolves through the link. Register no provisioning listener of your
    | own beside it: every listener shares SSO's one grant.
    |
    | Any other change that gives a person a principal (a membership created
    | or accepted, a platform principal created) reports it first, inside its
    | own transaction on the storage connection, before it writes the
    | principal: `Iam::scopeWidenings()->widen($identity, $tenantId, $client)`,
    | with `null` for a platform principal.
    |
    | `groups` maps the groups a provider reports (SSO's `groups` attribute) to
    | roles of `laravel-authorization`'s, each granted to the new identity in
    | the connection's tenant, never beyond it, in the same transaction, once
    | the link is made: a refusal, or a role that does not exist, rolls the
    | provisioning back. `mapping` names a class implementing
    | `SineMacula\Laravel\Iam\Contracts\GroupMapping`; with none named or
    | bound, `map` maps each group name to a role's name or a list of them;
    | with both empty, groups grant nothing. `resync` names a class
    | implementing `SineMacula\Laravel\Iam\Contracts\GroupResync`, which
    | every later sign-in through a connection calls with the groups then
    | reported, once the sign-in has committed, in a transaction of its own:
    | `SineMacula\Laravel\Iam\Provisioning\MappedGroupResync` makes the
    | identity's own roles in the connection's tenant exactly those the
    | mapping answers. Leave it null and nothing is re-synced: a person keeps
    | what provisioning granted until the application changes it. Provider
    | groups are only as trustworthy as the connection.
    |
    */

    'provisioning' => [
        'provisioner' => null,
        'groups'      => [
            'mapping' => null,
            'map'     => [],
            'resync'  => null,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Delivery
    |---------------------------------------------------------------------------
    |
    | The application's own gateways every member's codes are delivered
    | through, each named by its class: `email` implements
    | `SineMacula\Laravel\Iam\Contracts\EmailGateway` and `sms`
    | `SineMacula\Laravel\Iam\Contracts\SmsGateway`. Both are given the same
    | `SineMacula\Laravel\Iam\Delivery\CodeMessage`, whichever member issued the
    | code, and the application writes every message's wording and template.
    | A gateway bound in the container before this package registers counts as
    | named. Name none and nothing is pointed at it: MFA keeps its own senders,
    | which refuse to send (and MFA refuses to boot while an application offers
    | `sms` or `email` factors with them), and `laravel-authentication` keeps
    | its one-time code sender unbound.
    |
    | Naming a gateway points MFA's sender of that channel at it.
    | `laravel-authentication`'s one-time code sender is pointed at the gateways
    | once every gateway `types` routes to is named. `types` maps each of
    | `laravel-authentication`'s identifier types to the gateway its codes go
    | through (`email` or `sms`); a code MFA sends through
    | `laravel-authentication` goes through the gateway of its factor's own
    | channel. An MFA code goes through `laravel-authentication` only while its
    | one-time code sender is bound (this package's, or the application's) and
    | the factor is of MFA's own `sms` or `email` type, delivered by MFA's own
    | driver over this package's sender of its channel; MFA sends every other
    | code itself, through the sender or driver the application bound or
    | registered (`Mfa::extend()`), whenever it did so. Either way MFA's boot
    | check judges the senders its codes go through, so a factor type whose
    | gateway is not named (only `email` named with the shipped `types`, say,
    | while `sms` is offered) refuses boot rather than leave its codes
    | undelivered. A gateway bound after this package registers comes too late
    | to point a sender at it: name the gateways, or bind them before this
    | package registers. A code MFA sends itself is delivered synchronously,
    | inside MFA's transaction, so a gateway that throws leaves no code; one
    | `laravel-authentication` issues is delivered from that package's queued
    | job once the code has committed, so a gateway that throws fails the job
    | and the application's queue retries it under its own policy. A gateway's
    | return means the message was accepted for delivery, not received. This
    | package never queues or retries a delivery itself.
    |
    */

    'delivery' => [
        'email' => null,
        'sms'   => null,
        'types' => [
            'email' => 'email',
            'phone' => 'sms',
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | SSO
    |---------------------------------------------------------------------------
    |
    | `evidence` turns on SSO's per-connection evidence policy
    | (`SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy`), which
    | accepts the `amr`, `acr` and authentication context class values each
    | connection's own evidence settings list, within
    | `sso.linking.evidence_max_age_seconds`. Off, SSO keeps its default, which
    | accepts no provider's evidence. Either way the evidence SSO accepted is
    | only the first of two gates: what it satisfies is MFA's combination
    | policy's to decide, and MFA's default never counts a provider's `mfa` as
    | multifactor authentication; rebind MFA's combination policy to trust a
    | connection. Only `true` (as a boolean or as text, `1`, `on` or `yes`)
    | turns it on; anything else leaves it off. It applies only while
    | `adapters.sso` is on, and never replaces an evidence policy the
    | application bound itself.
    |
    */

    'sso' => [
        'evidence' => env('IAM_SSO_EVIDENCE', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Audit
    |---------------------------------------------------------------------------
    |
    | `mappers` records the members' own events in `laravel-audit-log`: one
    | mapper each for `laravel-authentication`'s, MFA's and SSO's events, and a
    | definition (version, category, the fields kept) for every code they
    | record that audit-log does not ship. Audit-log's own codes, such as
    | `authentication.signed_in`, are reused unchanged for an event that means
    | the same, so one query answers across guards. It is read as the package
    | boots, before audit-log stops taking registrations, so a change takes
    | effect on the next boot (a deploy, a worker restart). Turn it off
    | (`false`, `0`, `off`, `no`) only to map the members' events yourself; a
    | value it does not recognise leaves it on. Whatever it says, exclude every
    | `jwt` and `api_key` guard from audit-log's own capture
    | (`audit-log.capture.laravel.except_guards`) and leave its Gate capture
    | off, or each sign-in is recorded twice, and turn audit-log's
    | `definitions.require_registered` on, so a code without a definition is
    | refused rather than recorded unchecked. `iam:install` writes the
    | exclusions and the refusal into an audit-log configuration it publishes
    | (Gate capture already ships off), and `iam:check` refuses a
    | configuration without any of the three.
    |
    | `alerts` offers the suite's operational events to the application's
    | alerting: `audit_write_failed` (audit-log's `AuditWriteFailed`, a record
    | that could not be written), `audit_capture_failed` (`AuditCaptureFailed`,
    | an event a mapper could not describe), `integrity_check_failed`
    | (`IntegrityCheckFailed`, sealing or verification finding the log altered
    | or unverifiable) and `key_nearing_expiry` (SSO's `KeyNearingExpiry`, a key
    | or certificate within a configured threshold of its end). Name a listener
    | class, or a list of them, for each: it is resolved from the container and
    | handed the event through its `handle()` method, or invoked, synchronously,
    | in the order named, as the event is dispatched. The package sends nothing
    | itself, so with none named nobody is told. The values are read at each
    | dispatch: one that names no listener is refused then, and by `iam:check`.
    | Audit-log dispatches `AuditWriteFailed` and `AuditCaptureFailed` inside
    | its write guard, so a record their listener makes is refused; it does not
    | guard `IntegrityCheckFailed` (from `audit-log:seal` and `audit-log:verify`)
    | or SSO's `KeyNearingExpiry`, so their listener could record one, into the
    | very log just found altered or unverifiable for an integrity failure.
    | Alert by other means (a notification, a log channel) in every case.
    |
    */

    'audit' => [
        'mappers' => env('IAM_AUDIT_MAPPERS', true),
        'alerts'  => [
            'audit_write_failed'     => [],
            'audit_capture_failed'   => [],
            'integrity_check_failed' => [],
            'key_nearing_expiry'     => [],
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Transactions
    |---------------------------------------------------------------------------
    |
    | How many times a change that spans members is attempted, the first run
    | included, when it fails to serialise (SQLSTATE 40001), deadlocks or finds
    | SSO's link candidates changed. It is retried as a whole, and only when the
    | package opened the outermost transaction: inside a transaction the
    | application opened, the failure is rethrown for that transaction's owner
    | to retry. At least 1.
    |
    */

    'transactions' => [
        'attempts' => (int) env('IAM_TRANSACTION_ATTEMPTS', 3),
    ],

    /*
    |---------------------------------------------------------------------------
    | Workers
    |---------------------------------------------------------------------------
    |
    | Whether every member's request state is flushed as each Octane worker
    | starts, before each Octane request and
    | before each queued job not on the `sync` connection, so nothing one
    | request or job signed in (a guard, the session's proofs) reaches the
    | next. A `sync` job is skipped: it runs inside the request that dispatched
    | it, and keeps that request's guards and session.
    | Octane and the queue worker forget the container's scoped instances
    | themselves at each boundary; the worker's start, and
    | `Iam::resetWorkerState()`, forget the members' scoped state too. Turn it
    | off (`false`, `0`, `off`, `no`) only when the application performs the
    | same reset itself; any other value leaves it on. Long-lived processes of
    | any other kind call `Iam::resetWorkerState()` by hand between their units
    | of work.
    |
    */

    'workers' => [
        'reset' => env('IAM_WORKERS_RESET', true),
    ],
];
