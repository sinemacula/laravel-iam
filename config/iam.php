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
    | factor removal and reset, the return to pending, and the proof store. Each
    | adapter replaces only the member's own default, never a binding of the
    | application's. Turn it off (`false`, `0`, `off`) only to bind every one of
    | those seams yourself: revocation on factor removal is mandatory, and the
    | members' defaults leave it undone. A value it does not recognise leaves it
    | on.
    |
    */

    'adapters' => [
        'mfa' => env('IAM_ADAPTERS_MFA', true),
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
