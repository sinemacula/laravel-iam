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
    | first factor, code challenges and their counters, the event context, the
    | active tenant, the subject type, the active state and the application,
    | MFA's tenant requirement, answered from `tenancy.mfa_requirement`, the
    | passkey factor gate, and, while any MFA application offers the `passkey`
    | factor type, MFA's passkey ceremonies. Each adapter replaces only the
    | member's own default, never a binding of the application's. Turn it off
    | (`false`, `0`, `off`) only to bind every one of those seams yourself:
    | revocation on factor removal is mandatory, as is the passkey factor gate,
    | even once passkeys are no longer a factor type, and the members' defaults
    | leave both undone. A value it does not recognise leaves it on.
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
    | sign-in methods and email normaliser; while `sso.evidence` is on, SSO's
    | per-connection evidence policy; and the `sso` namespace of the
    | authentication context. SSO's freshness judges only a caller handed in:
    | wrap a call into SSO that asks it (a management helper, a link flow's
    | start) in `Iam::callers()->run($guard, $identity, $work)`; without one it
    | is stale. SSO keeps its own handoff codes either way. Turn it off
    | (`false`, `0`, `off`) only to bind every one of those seams yourself:
    | revocation is mandatory, since SSO's default leaves every session
    | standing when a tenant's enforcement changes, a connection is disabled or
    | deleted, a link is removed or a scope widened, and
    | `laravel-authentication`'s default links nothing, so no SSO sign-in
    | succeeds. A value it does not recognise leaves it on.
    |
    | While `sso` is on, the package also binds `laravel-authentication`'s
    | tenant authentication policy, answered from SSO's enforcement, SSO's
    | exemptions and the tenant MFA requirement together, whatever `mfa` says:
    | it finds the connection of a sign-in through the redemption this
    | package's SSO capability admitted, which nothing records with `sso` off.
    | With `sso` off, bind it yourself: it is mandatory while
    | `sso.features.enforcement` is on or a tenant MFA requirement is named or
    | bound, since `laravel-authentication`'s default requires nothing of any
    | tenant, so no enforcement and no requirement would reach a session.
    |
    */

    'adapters' => [
        'mfa' => env('IAM_ADAPTERS_MFA', true),
        'sso' => env('IAM_ADAPTERS_SSO', true),
    ],

    /*
    |---------------------------------------------------------------------------
    | Tenancy
    |---------------------------------------------------------------------------
    |
    | `mfa_requirement` names the application's tenant MFA requirement, a
    | class implementing `SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement`:
    | which further factors a session acting in a tenant must have, the
    | application's own data. The package hands its one answer to MFA's tenant
    | requirement while `adapters.mfa` is on, and to `laravel-authentication`'s
    | tenant authentication policy while `adapters.sso` is on, which it
    | answers from SSO's enforcement, SSO's exemptions and that requirement
    | together, with a version that changes when any of them does. With
    | `adapters.sso` off, bind that policy yourself (see Adapters); with both
    | off nothing of the package's reads it: bind both seams yourself. It
    | answers for exactly the tenant asked: the package applies no inheritance
    | down a tenant tree. A requirement bound in the container counts as
    | named. Name none (leave it null) and no tenant requires a further
    | factor; SSO's enforcement still applies. Any value that is no class name
    | (true, false, a number) fails closed.
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
    */

    'tenancy' => [
        'mfa_requirement' => null,
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
    | starts, before each Octane request and before each queued job, so nothing
    | one request or job bound (a signed-in guard, a member's scoped instance)
    | reaches the next. Turn it off (`false`, `0`, `off`) only when the
    | application performs the same reset itself; a value it does not recognise
    | leaves it on. Long-lived processes of any other kind call
    | `Iam::resetWorkerState()` by hand between their units of work.
    |
    */

    'workers' => [
        'reset' => env('IAM_WORKERS_RESET', true),
    ],
];
