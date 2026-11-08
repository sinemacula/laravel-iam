# Guides

Every guide to using the package, by what you are doing. Start with [Installation](installation.md), then read the guide
for each pair of members you use, and [An example application](example-application.md), which lays out the routes of
the flows this package changes and links to the members' guides for the rest. Read [Bindings](bindings.md) before you
bind any contract of your own.

This package is the glue between the five members of the suite. It binds each member's contracts to the others',
translates between their shapes, records their events in the audit trail and checks that the whole is configured
safely. What each member does on its own is in that member's guides, and these guides link to them rather than repeat
them.

The security and lifecycle contracts behind the guides, for maintainers and reviewers, are in
[docs/design](../design/README.md).

## Quick start

Require the package, which brings every member with it, and allow SSO's Composer plugin in your application's
`composer.json` (see [Installation](installation.md#requirements)):

```bash
composer require sinemacula/laravel-iam
```

Publish every member's configuration, language files and migrations, then migrate:

```bash
php artisan iam:install
php artisan migrate
```

The install command ends with what your application still owes: its gateways, its tenancy contracts, its provisioner,
its routes (following [An example application](example-application.md), which redeems SSO's handoffs through
`Iam::signIns()`, `Iam::reauthentications()` and `Iam::links()`), a definition registered with `AuditLog::define()`
for every audit code it records itself (audit-log refuses an unregistered one once `iam:install` has turned
`definitions.require_registered` on; see [The audit trail](audit-trail.md#codes)), and its schedule. Register the
scheduled work in `bootstrap/app.php`:

```php
use Illuminate\Console\Scheduling\Schedule;
use SineMacula\Laravel\Iam\Facades\Iam;

->withSchedule(function (Schedule $schedule): void {
    Iam::schedule($schedule);
})
```

Run the scheduler, and run a queue worker for `laravel-authentication`'s delivery of one-time codes
(`authentication.delivery.queue.connection` and `authentication.delivery.queue.name`): every code it sends, MFA's email
and SMS codes among them once the gateways are named, waits on that queue until a worker takes it. While SSO is in use,
the same worker, or one of its own, runs SSO's metadata refresh on `sso.metadata.queue` (see
[Operations](operations.md#queues)).

Then check the whole configuration, and do so again on every deploy:

```bash
php artisan iam:check
```

It runs every member's own check and this package's, and exits non-zero on any failure.

## Setup

| Guide                             | Covers                                                                                   |
|-----------------------------------|------------------------------------------------------------------------------------------|
| [Installation](installation.md)   | Requirements, `iam:install`, the storage connection, guards, and moving from the members |
| [Configuration](configuration.md) | Every key of `config/iam.php`                                                            |
| [Bindings](bindings.md)           | Every binding: what it is bound to, how to replace it, and what replacing it risks       |
| [Checks](checks.md)               | Every check `iam:check` makes, and what fixes each                                       |

## The members together

| Guide                                                   | Covers                                                                        |
|---------------------------------------------------------|-------------------------------------------------------------------------------|
| [Authentication and MFA](authentication-and-mfa.md)     | Pending sign-ins, step-up, requirements, factor changes, codes, passkeys      |
| [Authentication and SSO](authentication-and-sso.md)     | Redeeming handoff codes, links, re-authentication, revocation, freshness      |
| [MFA and SSO](mfa-and-sso.md)                           | A provider's evidence, the two gates it passes, and tenants' requirements     |
| [Authorization](authorization.md)                       | What is installed now, and what waits for `laravel-authorization`             |
| [Provisioning and tenancy](provisioning-and-tenancy.md) | The provisioner, memberships, the tenant tree and the tenant requirement      |
| [The audit trail](audit-trail.md)                       | Codes, categories, correlation, double records and operational alerts         |
| [An example application](example-application.md)        | Routes and controllers for the flows this package changes, as an example only |

## Running it

| Guide                       | Covers                                                                      |
|-----------------------------|-----------------------------------------------------------------------------|
| [Operations](operations.md) | The schedule, every key and `APP_KEY` rotation, retries, workers and Octane |
| [Testing](testing.md)       | Acting as a caller in one call, the fakes and the contract kits             |

## The members' own guides

| Member                              | Guides                                                         |
|-------------------------------------|----------------------------------------------------------------|
| `sinemacula/laravel-authentication` | [docs/guides][authentication-guides]                           |
| `sinemacula/laravel-mfa`            | [docs/guides][mfa-guides]                                      |
| `sinemacula/laravel-sso`            | [docs/guides][sso-guides], [its index][sso-index]              |
| `sinemacula/laravel-audit-log`      | [docs/guides][audit-log-guides]                                |
| `sinemacula/laravel-authorization`  | [README][authorization-readme] (it has no separate guides yet) |

[authentication-guides]: https://github.com/sinemacula/laravel-authentication/tree/master/docs/guides
[mfa-guides]: https://github.com/sinemacula/laravel-mfa/tree/master/docs/guides
[sso-guides]: https://github.com/sinemacula/laravel-sso/tree/master/docs/guides
[sso-index]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/README.md
[audit-log-guides]: https://github.com/sinemacula/laravel-audit-log/tree/master/docs/guides
[authorization-readme]: https://github.com/sinemacula/laravel-authorization/blob/master/README.md
