# Installation

This package installs the five members of the suite and binds them together. One `composer require` brings every
member, one command publishes their files, and one check confirms the whole is configured safely. What each member
asks of you on its own is in its installation guide; this guide covers what changes when they are installed together,
and what the package leaves to your application.

## Requirements

- PHP `^8.3`, with the `bcmath`, `curl`, `dom`, `hash`, `libxml`, `mbstring`, `openssl` and `zlib` extensions. These
  are the extensions every member needs together, and the package declares them, so Composer refuses to install the
  suite where one is missing.
- Laravel `^12.40` or `^13.3`.
- SSO's Composer plugin, `simplesamlphp/composer-xmlprovider-installer`, allowed in your application's own
  `composer.json`. A package cannot allow a plugin for the application, so this is yours to add:

```json
{
    "config": {
        "allow-plugins": {
            "simplesamlphp/composer-xmlprovider-installer": true
        }
    }
}
```

`iam:check` reports a missing extension, and a plugin that is not installed or whose files are not linked (allow it,
then run `composer install` again). See [Checks](checks.md).

## Installing

```bash
composer require sinemacula/laravel-iam
```

This requires `sinemacula/laravel-authentication`, `sinemacula/laravel-authorization`, `sinemacula/laravel-mfa`,
`sinemacula/laravel-sso` and `sinemacula/laravel-audit-log`. Every member is required: none is optional, and each
member's service provider must register with the others, as package discovery registers them. When
`laravel-authentication`'s, MFA's, SSO's or audit-log's provider has still not registered once the application has
booted, the boot is refused (`SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException`), since nothing aligned
its storage or registered its audit mapping.

## Publishing

```bash
php artisan iam:install
```

`iam:install` publishes, in a fixed order, every member's configuration, language files and migrations
(`laravel-authentication`, `laravel-authorization`, `laravel-mfa`, `laravel-sso`, then `laravel-audit-log`), and
this package's `config/iam.php` last. Each file goes where its own member's provider publishes it.

It never overwrites anything, and is safe to run twice:

- a configuration or language file already in place is kept as it is;
- a migration already published is recognised by its name without the timestamp, whatever timestamp it was published
  under, and is never published a second time;
- a migration of your own that shares a member migration's name (`create_rate_limits_table`, say) is not taken for
  the member's: the member's is published beside it and the run fails, naming both, so you can check the two create no
  table in common before you migrate. A later run recognises the member's copy and passes. One namesake does not fail
  the run: a namesake of one of `laravel-authorization`'s migrations (`create_roles_table`, say) in a run that writes
  the table prefix (see [Prefixing the authorization tables](#prefixing-the-authorization-tables)) is reported as a
  note, since the two then create different tables, unless an `AUTHORIZATION_TABLE_*` variable you set names the
  table yours creates: check those variables before you migrate.

Where it publishes `config/audit-log.php` itself, it writes two values into it: every `jwt` and `api_key` guard into
`capture.laravel.except_guards`, and `definitions.require_registered` on. Without them each sign-in would be recorded
twice and a code with no definition recorded unchecked (see [The audit trail](audit-trail.md)). A
`config/audit-log.php` you published before is never written to: each value it lacks is listed as owed instead. With
`definitions.require_registered` on, every audit code your application records itself must have a definition
registered with `AuditLog::define()` before it is recorded, or recording it throws (see
[Your own codes](audit-trail.md#codes)).

### Prefixing the authorization tables

While none of `laravel-authorization`'s files has been published yet, the command offers a prefix for its table names,
or takes one from the option:

```bash
php artisan iam:install --prefix=iam_
```

The prefix is lower-case letters, digits and underscores, starts with a letter, and is at most 16 characters, so every
name the migrations derive stays within PostgreSQL's and MySQL's limits. It is written into the published
`config/authorization.php` as the default of each `AUTHORIZATION_TABLE_*` variable, so a variable you set still wins.
A table `laravel-authorization` already ships under a name starting with the prefix keeps that name, rather than
carrying the prefix twice. With `--no-interaction` the command asks
nothing and prefixes nothing unless the option says so. Once any of the member's files is published the tables have
their names, so a prefix is no longer offered.

### What you still owe

Every run ends with what the application still owes. The package cannot do these for you:

| Owed                                                                                                                                                                                                                                                          | Where it is covered                                                         |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| Run `php artisan migrate`                                                                                                                                                                                                                                     | [The storage connection](#the-storage-connection)                           |
| Bind `laravel-authentication`'s `OneTimeCodeSender`                                                                                                                                                                                                           | [Authentication and MFA](authentication-and-mfa.md#codes-and-delivery)      |
| Name or bind your tenant MFA requirement, memberships and tenant tree                                                                                                                                                                                         | [Provisioning and tenancy](provisioning-and-tenancy.md)                     |
| Bind `laravel-authentication`'s `TenantResolver` before you grant in a tenant while the authorization and SSO adapters are on (the default), name a tenant MFA requirement or turn SSO's enforcement on, even if your principals act only in their own tenant | [Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-resolver) |
| Name or bind your provisioner                                                                                                                                                                                                                                 | [Provisioning and tenancy](provisioning-and-tenancy.md#provisioning)        |
| Add the routes, following laravel-iam's example application guide: redeem SSO's handoffs through `Iam::signIns()`, `Iam::reauthentications()` and `Iam::links()`, never `HandoffRedemption` directly                                                          | [An example application](example-application.md)                            |
| Call `Iam::schedule()` and run the scheduler                                                                                                                                                                                                                  | [Operations](operations.md#the-schedule)                                    |
| Run a queue worker for `laravel-authentication`'s code delivery and, while SSO is in use, SSO's metadata refresh                                                                                                                                              | [Operations](operations.md#queues)                                          |
| Allow SSO's Composer plugin                                                                                                                                                                                                                                   | [Requirements](#requirements)                                               |
| Map each application to its permission in `authorization.application_access`, and bind `TenantAccess` if your principals act beyond their own tenant                                                                                                          | [Authorization](authorization.md#access-contracts)                          |
| Declare MFA's and SSO's freshness operations for their guards                                                                                                                                                                                                 | [Guards and applications](#guards-and-applications)                         |
| Keep every `jwt` and `api_key` guard excluded from audit-log's capture                                                                                                                                                                                        | [The audit trail](audit-trail.md#no-double-records)                         |
| Define every audit code your application records itself                                                                                                                                                                                                       | [The audit trail](audit-trail.md#codes)                                     |
| Run `php artisan iam:check` on every deploy                                                                                                                                                                                                                   | [Checks](checks.md)                                                         |

A run fails (exit code 1) when a tag it publishes is not registered, when a migration's identity is in doubt, or when a
file cannot be copied; what it published before the failure is kept, and running it again publishes the rest.

## The storage connection

`laravel-authentication`'s, MFA's and SSO's tables live on one database connection, so a change that spans them
commits or rolls back as one. Name it once:

```dotenv
IAM_STORAGE_CONNECTION=mysql
```

Leave it unset for the default connection. The package writes it into `authentication.storage.connection`,
`mfa.storage.connection`, `sso.storage.connection` and `laravel-authorization`'s `authorization.connection` wherever you
leave them unset. A member key that names another connection refuses the boot
(`SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException`): unset it, or set it to the same connection.
`laravel-audit-log`'s tables follow `audit-log.storage.connection`, the default connection when unset.

Your own models belong on that connection too:

- **Identity models.** The model of every user provider a `jwt` or `api_key` guard uses must live on the storage
  connection: the members read and lock identities inside their transactions on it. `iam:check` reads each model's
  connection and refuses one on another.
- **Principal models.** No setting names them, so no check can find them: keep every principal model your identities
  hold (`HasPrincipals`) on the storage connection as well. A principal written on another connection is not atomic
  with the members' writes beside it: a provisioned membership with the link SSO writes, a new principal with the scope
  widening reported before it.
- **Tenant, membership and tree tables.** Your provisioner, memberships and tenant tree read and write on the storage
  connection for the same reason (see [Provisioning and tenancy](provisioning-and-tenancy.md)).

Leave the connection fixed while the application runs. Moving the tables is a deploy: a migration you perform, and a
restart of every worker.

## Guards and applications

Each application is one of `laravel-authentication`'s `jwt` guards, and MFA's and SSO's applications are named after
the guard they sign people in on. Declare the guard first (see `laravel-authentication`'s
[installation guide][authentication-installation]), then its MFA application and its SSO application under the same
name:

```php
// config/auth.php
'guards' => [
    'api' => [
        'driver'      => 'jwt',
        'provider'    => 'users',
        'application' => ['methods' => ['password', 'external_provider']],
    ],
],

// config/mfa.php
'applications' => [
    'api' => [
        'types'       => ['totp', 'email'],
        'requirement' => 'enrolled',
    ],
],

// config/sso.php
'applications' => [
    'api' => ['redirect_uri' => 'https://app.example.test/sso'],
],
```

- An MFA application whose name is no guard in `auth.guards` is refused by `iam:check`.
- An SSO application's guard must allow `external_provider` among its methods: that, not SSO's own
  `external_sign_in` setting, decides whether people may sign in through a provider. Leave
  `sso.applications.*.unlinked_handoffs` off: under this package an unlinked sign-in is provisioned or refused, never
  handed off.
- MFA's first factor needs no `first_factor` entry: it is read from the session `laravel-authentication` signed the
  person in with.
- Declare every freshness operation MFA names (`mfa.add_factor`, `mfa.replace_factor`, `mfa.remove_factor`,
  `mfa.generate_recovery_codes`) for each MFA application's guard, and while SSO is in use every operation SSO names
  (`sso.connection.trust`, `sso.link.create` and the rest of SSO's [freshness operations][sso-freshness]) for each SSO
  application's guard, under `authentication.freshness` or the guard's own `freshness` block. How fresh each must be is
  your decision, and where a member asks a maximum age of its own the stricter of the two applies; `iam:check` refuses
  an operation left out. Each entry takes the shape of `laravel-authentication`'s own (see its
  [configuration guide][authentication-configuration]):

```php
// config/authentication.php
'freshness' => [
    // ...laravel-authentication's own operations, then one entry for every operation MFA and SSO name
    'mfa.remove_factor' => ['max_age_seconds' => 900, 'proofs' => ['additional_factor', 'recovery_code']],
    'sso.link.create'   => ['max_age_seconds' => 300, 'proofs' => ['first_factor', 'first_factor_reauthentication']],
],
```

Every `jwt` and `api_key` guard you add later goes into `audit-log.capture.laravel.except_guards` too.

## Partial suites

Every member is installed, but a feature you have not configured stays off. With neither `sso.features.saml2` nor
`sso.features.oidc` on, SSO is not in use: it starts no flow, and the checks of SSO's side (its applications' guards,
its links) do not apply. The adapters stay bound all the same, so turning a protocol on later needs nothing more from
this package. Three switches turn the package's adapters off altogether,
`IAM_ADAPTERS_MFA`, `IAM_ADAPTERS_SSO` and `IAM_ADAPTERS_AUTHORIZATION`. Turn one off only to bind every one of its
seams yourself: some are mandatory, and their members' defaults leave sessions standing that should end, or, for
`laravel-authorization`, know no session, tenant or scopes of `laravel-authentication`'s. See [Configuration](configuration.md)
and [Bindings](bindings.md).

## Checking

```bash
php artisan iam:check
```

Run it after installing and on every deploy. It runs `authentication:check`, `authorization:check`, `mfa:check`,
`sso:check` and `audit-log:check`, then this package's own checks, and exits non-zero on any failure. See
[Checks](checks.md) for every check and what fixes it.

## Moving from installing the members directly

An application that required the members one by one and wired them together itself moves onto this package without
publishing anything twice.

1. Line up the storage connection first, before you require this package. The package refuses the boot
   (`SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException`) whenever a member's storage key
   (`authentication.storage.connection`, `mfa.storage.connection`, `sso.storage.connection`) names a connection other
   than `iam.storage.connection`, which is the default connection when unset. Until they agree, every request and
   every command but `config:cache`, `config:clear`, `config:show`, `help`, `list`, `optimize:clear`,
   `package:discover` and `iam:check` refuses to boot, `iam:install` and `migrate` among them. So, while the members'
   tables share a dedicated connection, set `IAM_STORAGE_CONNECTION` to it; while they are on the default connection,
   unset the member keys, or set each to the default connection. Tables on
   different connections must first be moved onto one, by a migration you perform, before the package is required
   (see [The storage connection](#the-storage-connection)).
2. Require this package. Each member stays installed, now as its dependency; drop the members from your own
   `require` unless you pin one on purpose.

   ```bash
   composer require sinemacula/laravel-iam
   ```

3. Run `php artisan iam:install`. Every configuration and language file you published is kept, every migration you
   published is recognised whatever its timestamp, and only what is missing is published, `config/iam.php` among it.
   Run `php artisan migrate` for anything new.
4. Read what the run owes. Your `config/audit-log.php` is yours, so the install does not write it: add every `jwt` and
   `api_key` guard to `capture.laravel.except_guards` and turn `definitions.require_registered` on yourself. Before
   you turn it on, register a definition with `AuditLog::define()` for every audit code your application records
   itself: codes audit-log recorded under its permissive default are refused once it is on, and every
   `AuditLog::record()` of one throws (see [The audit trail](audit-trail.md#codes)). A table prefix for
   `laravel-authorization` is no longer offered once its files exist.
5. Replace your own redemption of SSO's handoff codes. A direct install redeems a code through SSO's
   `SineMacula\Laravel\Sso\Handoffs\HandoffRedemption` (`admit()` or `redeem()`) and then hands the result to
   `laravel-authentication`'s `signInExternally()` or `reauthenticateExternally()`. Under this package, its
   `ExternalIdentityLinks` adapter finds a link only from a redemption the package's own core methods recorded, so
   that route stops finding links once the package binds its adapter. `iam:check` cannot see a route.
   Replace every such controller with `Iam::signIns()->redeem()`, `Iam::reauthentications()->redeem()` and
   `Iam::links()->redeem()`, as [Signing in through SSO](example-application.md#signing-in-through-sso) shows.
6. Remove the glue you wrote. Your own binding of a member's contract always wins over this package's adapter, so an
   adapter you wrote for a seam this package binds keeps running in its place. `iam:check` cannot find all of them:
   it notes only a binding made before this package registers (`note: ... keeps the application's binding`), and
   package providers register before your application's, so a binding in your own service provider's `register()` or
   `boot()`, the usual place, replaces the adapter silently, and is checked only if the seam is mandatory. Search your
   providers for every contract [Bindings](bindings.md) lists, and remove each binding yourself unless you mean to keep
   it. In particular remove:
   - your own listener of SSO's `ResultUnlinked` that provisions people: name your provisioner instead (see
     [Provisioning and tenancy](provisioning-and-tenancy.md#provisioning)), and register no provisioning listener
     beside the package's;
   - your own audit mappers of the members' events, or turn `IAM_AUDIT_MAPPERS` off to keep them;
   - your own senders of MFA's codes: bind `laravel-authentication`'s `OneTimeCodeSender`, which receives them too.
7. In your tests, keep MFA's `actingAsVerified()` where the guard allows the `password` method, or use this package's
   helpers (see [Testing](testing.md)).
8. Run `php artisan iam:check`.

[authentication-installation]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/installation.md
[authentication-configuration]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/configuration.md
[sso-freshness]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/freshness.md
