<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | `connection`: the one connection every member's tables live on, `null` for
    | the default. It fills each member's unset `storage.connection`; a member
    | naming another connection refuses boot.
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
    | Which members this package binds together; each is on by default. An
    | adapter replaces only a member's own default, never the application's
    | binding. Turn one off only to bind its seams yourself: `iam:check`
    | refuses the members' defaults on the seams that are mandatory.
    |
    | `mfa`: binds `laravel-authentication` and MFA through each other's seams.
    | `sso`: binds `laravel-authentication` and SSO, and the tenant
    | authentication policy; SSO's membership seams also need
    | `SineMacula\Laravel\Iam\Contracts\Memberships` bound.
    | `authorization`: binds `laravel-authorization` to the other members.
    |
    */

    'adapters' => [
        'mfa'           => env('IAM_ADAPTERS_MFA', true),
        'sso'           => env('IAM_ADAPTERS_SSO', true),
        'authorization' => env('IAM_ADAPTERS_AUTHORIZATION', true),
    ],

    /*
    |---------------------------------------------------------------------------
    | Provisioning
    |---------------------------------------------------------------------------
    |
    | `groups.map`: provider group name => role name, or a list of them,
    | granted in the connection's tenant on first sign-in. Ignored when a
    | `SineMacula\Laravel\Iam\Contracts\GroupMapping` is bound.
    |
    */

    'provisioning' => [
        'groups' => [
            'map' => [],
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | SSO
    |---------------------------------------------------------------------------
    |
    | `evidence`: binds SSO's per-connection evidence policy while
    | `adapters.sso` is on. Off by default, so no provider's evidence counts.
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
    | `mappers`: records the members' events in `laravel-audit-log`. On by
    | default; read at boot, so a change needs a restart.
    |
    */

    'audit' => [
        'mappers' => env('IAM_AUDIT_MAPPERS', true),
    ],

    /*
    |---------------------------------------------------------------------------
    | Transactions
    |---------------------------------------------------------------------------
    |
    | `attempts`: how many times `Iam::transaction()` runs a change that hits a
    | concurrency failure, the first included. Only the outermost retries.
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
    | `reset`: flushes the members' request state as each Octane worker starts,
    | before each Octane request and before each non-`sync` queued job. On by
    | default.
    |
    */

    'workers' => [
        'reset' => env('IAM_WORKERS_RESET', true),
    ],
];
