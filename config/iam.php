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
    | factor removal and reset, the return to pending, the proof store, code
    | challenges and their counters, the event context, the active tenant, the
    | subject type and the application, the passkey factor gate, and, while any
    | MFA application offers the `passkey` factor type, MFA's passkey
    | ceremonies. Each adapter replaces only the member's own default, never a
    | binding of the application's. Turn it off (`false`, `0`, `off`) only to
    | bind every one of those seams yourself: revocation on factor removal is
    | mandatory, as is the passkey factor gate, even once passkeys are no longer
    | a factor type, and the members' defaults leave both undone. A value it
    | does not recognise leaves it on.
    |
    */

    'adapters' => [
        'mfa' => env('IAM_ADAPTERS_MFA', true),
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
