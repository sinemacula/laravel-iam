# Operations

What running the suite asks of you: the scheduled work and the queues, every key the suite uses and what rotating
`APP_KEY` affects, retrying a change that fails to serialise, and the reset between requests and jobs in long-lived
processes. Each member's own operations are in its guide: `laravel-authentication`'s [operations][auth-operations],
MFA's [operations][mfa-operations], SSO's [operations][sso-operations] and [long-running processes][sso-long-running],
and audit-log's [operations][audit-operations].

## On every deploy

1. Run `php artisan migrate` for anything a new release published.
2. Run `php artisan iam:check`, and stop the deploy when it exits non-zero (see [Checks](checks.md)).
3. Restart every long-lived process (`php artisan octane:reload`, `php artisan queue:restart`), so each one boots with
   the new code and configuration. The audit mappings, the storage connection and the bindings are read as the
   application boots.

## The schedule

Register the members' scheduled work in one call, from `bootstrap/app.php`:

```php
use Illuminate\Console\Scheduling\Schedule;
use SineMacula\Laravel\Iam\Facades\Iam;

->withSchedule(function (Schedule $schedule): void {
    Iam::schedule($schedule);
})
```

and run Laravel's scheduler. It registers:

| Task                                                                                                       | When                                                        |
|------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| `mfa:prune`                                                                                                | daily                                                       |
| `authorization:prune`                                                                                      | daily                                                       |
| SSO's operations schedule: `sso:prune`, `sso:domains:recheck`, `sso:metadata:refresh`, `sso:keys:expiring` | at `sso.operations.cadence.*`, and only while SSO is in use |
| `audit-log:drain --until-empty`                                                                            | every minute, while `audit-log.delivery.mode` is `outbox`   |

- Audit-log registers its own sealing, sweep, verification and pruning on the schedule itself, so `Iam::schedule()`
  never registers them again. `iam:check` notes any of them switched off with nothing else running it.
- `sso:prune` is registered only through SSO's own schedule, so it runs once. With `sso.operations.cadence.prune`
  switched off, schedule `sso:prune` yourself.
- None of this package's tasks takes a cache mutex. SSO's take one only while `sso.operations.cache_mutexes` is on
  (off by default): SSO's schedule then adds `withoutOverlapping()` for `sso.operations.mutex_minutes` and
  `onOneServer()` to each of its tasks, which needs a cache store every server shares and can lock. Every command is
  safe to run on several servers at once without them ([laravel-sso: several servers, and the
  cache][sso-several-servers]).
- A malformed SSO cadence is SSO's own `InvalidArgumentException`, thrown as the schedule is built, so the scheduler
  never starts with it.
- `authorization:prune` removes `laravel-authorization`'s expired grants and those of grantees and records that are
  gone. An expired grant stops counting at its expiry whether or not the prune has run, so it keeps the grant tables
  small rather than making a check correct. It is registered whatever `iam.adapters.authorization` says.
- `laravel-authentication`'s expired rows are pruned by Laravel's `model:prune`, which you schedule with its models
  named, as its [operations guide][auth-pruning] shows.

### Queues

Run a queue worker for:

- SSO's metadata refresh, on `sso.metadata.queue`;
- `laravel-authentication`'s delivery of one-time codes, MFA's email and SMS codes among them, on
  `authentication.delivery.queue.connection` and `authentication.delivery.queue.name`. A gateway that throws fails the
  job, and your queue retries it under its own policy.

Audit-log's outbox uses no queue. With `audit-log.delivery.mode` set to `outbox`, records wait in the outbox table until
`audit-log:drain --until-empty`, which `Iam::schedule()` registers every minute (the table above), delivers them to the
store. So Laravel's scheduler must run (`schedule:run` every minute, or `schedule:work`) wherever your other scheduled
tasks live; a queue worker drains nothing, and without the scheduler no record reaches the store.

## Secrets and key rotation

Every key the suite uses, which member uses it, and what rotating it does. This package keeps no key of its own.

| Key                                                                    | Member                   | Protects                                                                                               |
|------------------------------------------------------------------------|--------------------------|--------------------------------------------------------------------------------------------------------|
| `authentication.jwt.keys`, `authentication.jwt.active_kid`             | `laravel-authentication` | the signature of every access and refresh token of a guard that sets no `jwt.keys` of its own          |
| `auth.guards.<name>.jwt.keys`, `auth.guards.<name>.jwt.active_kid`     | `laravel-authentication` | the signature of that guard's tokens, when the guard sets its own                                      |
| `authentication.codes.key`                                             | `laravel-authentication` | the keyed digests of one-time codes and password reset links, MFA's codes issued through it among them |
| `audit-log.integrity.keys`, `audit-log.integrity.current`              | `laravel-audit-log`      | each entry's HMAC, each seal and the journal                                                           |
| `audit-log.privacy.keys`, `audit-log.privacy.current`                  | `laravel-audit-log`      | the wrapping of every owner's data key                                                                 |
| `audit-log.redaction.key`                                              | `laravel-audit-log`      | the keyed hashes of sign-in identifiers and pseudonymised fields                                       |
| SSO's service provider keys (`sso_keys`, managed by SSO's key service) | `laravel-sso`            | signing requests, decrypting assertions, client assertions                                             |
| `app.key`, `app.previous_keys`                                         | every member             | see [Rotating `APP_KEY`](#rotating-app_key)                                                            |

### JWT signing keys

`authentication.jwt.keys` is a map of kid to secret (`AUTHENTICATION_JWT_KEY` for the shipped `default`), and
`authentication.jwt.active_kid` (`AUTHENTICATION_JWT_ACTIVE_KID`) names the one that signs new tokens. To rotate, add
the new kid beside the current one, point `active_kid` at it, and remove the old kid once every token signed under it
has expired: at most the absolute session lifetime after the switch. Removing a kid at once rejects every token signed
under it, which is also how to revoke a compromised key. See `laravel-authentication`'s
[key rotation][auth-key-rotation].

A `jwt` guard whose `config/auth.php` entry sets its own `jwt.keys` signs and verifies its tokens with that map alone,
never with `authentication.jwt.keys`, so it is rotated, and a compromised key revoked, in that guard's own block:
removing a kid from `authentication.jwt.keys` revokes nothing that guard signed. Follow the same steps in
`auth.guards.<name>.jwt.keys` and `auth.guards.<name>.jwt.active_kid`. `keys` and `active_kid` fall back to the
package-wide values independently, so a guard that overrides `keys` must also set its own `active_kid` to a kid in its
own map. Left to the package-wide `active_kid`, the guard looks for that kid in its own map, and when the map does not
hold it, as once the steps above point `authentication.jwt.active_kid` at a new kid, the guard's token service fails to
build with an `InvalidJwtConfigurationException` and the guard signs no one in. A guard that sets neither follows
`authentication.jwt.*`. See `laravel-authentication`'s [per-guard JWT configuration][auth-per-guard-jwt].

### The code key

`authentication.codes.key` (`AUTHENTICATION_CODES_KEY`, at least 32 bytes) keys the digests of every one-time code
`laravel-authentication` stores, an MFA email or SMS code issued through it included, and of every password reset link's
token, which is a one-time code too, not a signed link. Unset, it is derived from `app.key` alone, never from
`app.previous_keys`. Rotating it, or `app.key` while it is derived, invalidates the codes and reset links outstanding,
at once and whatever `APP_PREVIOUS_KEYS` lists: the person asks for another. It also restarts every destination's
delivery window: `laravel-authentication` keys each destination's window by a digest under a key derived from the code
key, so after a rotation no window matches, and every destination's `authentication.codes.max_deliveries` cap and
`authentication.codes.resend_cooldown_seconds` cooldown start again, for every code it issues (MFA's email and SMS
codes, password reset and identifier verification codes among them). Rotating the code key alone leaves the
`code_request` rate limits, keyed from `app.key`, in place. Set one before going live, so an `APP_KEY` rotation does not
reach it, and do not rotate it during an attack on sending limits unless the key itself is compromised (see [Rotating
`APP_KEY`](#rotating-app_key)).

### Audit-log's keys

- **The integrity ring** (`integrity.keys`, `integrity.current`, `AUDIT_LOG_INTEGRITY_CURRENT`) signs every entry and
  seal, and decides how long the log can be verified. Rotate by adding a key and pointing `current` at it; keep every
  ring key for as long as the entries and seals it signed. Use a managed ring before going live: keys derived from
  `app.key` tie the log to it, and the old `app.key` must then stay in `app.previous_keys` for as long as the log.
- **The wrapping keys** (`privacy.keys`, `privacy.current`, `AUDIT_LOG_PRIVACY_CURRENT`) wrap each owner's data key.
  Rotate by adding a key, pointing `current` at it, and running `audit-log:rewrap`; drop the old one only once a run
  ends `complete`.
- **The redaction key** (`redaction.key`, `AUDIT_LOG_REDACTION_KEY`) keys the hashes of sign-in identifiers and the
  pseudonymised fields this package's codes keep, such as an identifier change's identifiers. Changing it breaks
  correlation with earlier rows.

Every lifetime is in audit-log's [keys and their lifetimes][audit-keys].

### SSO's keys

SSO's service provider keys and certificates are generated, published, made current and retired through SSO's key
service, without downtime, in four steps (see SSO's [keys guide][sso-keys]); `sso.keys.*` sets their size, validity and
overlap. A key or certificate nearing its end is reported by `sso:keys:expiring`, which `Iam::schedule()` runs, as
SSO's `KeyNearingExpiry` event, which you listen to (see [The audit trail](audit-trail.md#operational-alerts)). Their
private keys, like every connection's client secret, are stored encrypted under `APP_KEY` by default.

### Rotating `APP_KEY`

Laravel decrypts with `APP_KEY` and then each key in `APP_PREVIOUS_KEYS`, and most of what the suite keeps under it
needs no migration. Rotate it like this:

1. Generate a new key, and move the current one to `APP_PREVIOUS_KEYS` (comma-separated when there are several):

   ```dotenv
   APP_KEY=base64:new...
   APP_PREVIOUS_KEYS=base64:old...
   ```

2. Deploy and restart every worker (`php artisan octane:reload`, `php artisan queue:restart`), so each builds Laravel's
   encrypter with the new keys.
3. Keep the old key listed for as long as anything below still needs it.

What it affects, member by member:

| Member                   | Under `APP_KEY`                                                                                                             | On rotation                                                                                                                                                       |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `laravel-mfa`            | every TOTP factor's secret, encrypted                                                                                       | keep the old key while any factor enrolled before the rotation exists                                                                                             |
| `laravel-mfa`            | the digests of the codes it delivers, its attempt throttles and its send caps                                               | outstanding codes stop working; throttles and send caps start afresh, lockouts are kept                                                                           |
| `laravel-sso`            | client secrets, private keys, stored handoff results and provider-side verifiers, encrypted                                 | keep the old key until every secret is set again under the new one                                                                                                |
| `laravel-sso`            | its rate-limit counters                                                                                                     | every counter starts afresh                                                                                                                                       |
| `laravel-authentication` | signed links (an identifier verification, an identifier change), signed                                                     | links signed under the old key keep working while it is listed                                                                                                    |
| `laravel-authentication` | the code key, when `authentication.codes.key` is unset: one-time codes, password reset links and delivery windows           | outstanding codes and password reset links stop working at once: the code key reads no previous key; every destination's delivery cap and resend cooldown restart |
| `laravel-authentication` | its rate-limit counters, and every queued delivery (codes, password resets, identifier change codes and notices), encrypted | counters start afresh; keep the old key until the queue has drained                                                                                               |
| `laravel-audit-log`      | the outbox and manifests, encrypted; the integrity, wrapping and redaction keys when derived                                | keep the old key as audit-log's [keys guide][audit-keys] says; a derived redaction key breaks correlation                                                         |
| `laravel-authorization`  | nothing                                                                                                                     | nothing                                                                                                                                                           |

Rotating `APP_KEY` restarts the rate-limit counters of `laravel-authentication` and SSO, and MFA's throttles and send
caps, and, while the code key is derived from it, every destination's delivery cap and resend cooldown, so each limit
allows a fresh allowance at once: every destination may be sent codes again straight away. Rotating an explicit
`authentication.codes.key` restarts the delivery caps and cooldowns the same way ([The code key](#the-code-key)). Do not
rotate either key during an attack on those limits (code guessing, or sending codes to numbers that charge for them)
unless the key itself is compromised.

A key dropped from both `APP_KEY` and `APP_PREVIOUS_KEYS` while something still needs it leaves that unreadable: TOTP
factors fail to verify and their holders need another factor or a reset, and an SSO secret that no key decrypts is a
server error, never a failed sign-in. Set the code key and audit-log's rings explicitly before going live, so an
`APP_KEY` rotation reaches as little as possible. See MFA's [secrets guide][mfa-secrets] and SSO's
[secrets guide][sso-secrets].

## Retries

A change that spans members runs in one transaction on the storage connection, through `Iam::transaction()`:

```php
use App\Models\Member;
use SineMacula\Laravel\Iam\Facades\Iam;

$member = Iam::transaction(function () use ($identity, $tenantId, $client): Member {
    Iam::scopeWidenings()->widen([$identity], $tenantId, $client);

    return Member::create(['user_id' => $identity->getAuthIdentifier(), 'tenant_id' => $tenantId]);
});
```

Each member's own transaction inside it is a savepoint, so all of it commits or rolls back as one.

- **When it is retried.** It runs through Laravel's `transaction($work, $attempts)`, so only when it opens the outermost
  transaction: a serialisation failure, a deadlock, a lock wait timeout or SSO's `LinkCandidatesChanged` runs the whole
  closure again, up to `iam.transactions.attempts` (`IAM_TRANSACTION_ATTEMPTS`, 3 by default) or the attempts you pass.
  The last one is rethrown as a `DeadlockException` with SQLSTATE 40001, the original as its previous.
- **Inside your own transaction** it runs once and rethrows, in a form your own `DB::transaction($work, $attempts)`
  recognises.
- **Keep the closure to database work.** On a retry everything in it runs again. A failure after the commit is never
  retried.
- **Flows a member opens itself cannot be wrapped**: MFA's verifications, factor changes, removals and resets, and
  `Iam::links()`, which SSO redeems in its own transaction. Retry the request when one fails to serialise (see
  [Authentication and MFA](authentication-and-mfa.md#transactions-and-retries)).
- **SSO's starts and completions** talk to the provider and refuse to run inside a transaction.

The sign-in and re-authentication redemptions (`Iam::signIns()`, `Iam::reauthentications()`) open their own, retried
the same way.

## Workers and Octane

Nothing one request or job binds may reach the next. With `iam.workers.reset` on (`IAM_WORKERS_RESET`, the default),
the package resets every member's request state at each boundary:

| When                                | What is reset                                                                  |
|-------------------------------------|--------------------------------------------------------------------------------|
| An Octane worker starts             | everything below, and the members' scoped state the worker's boot left         |
| Before each Octane request          | every `laravel-authentication` guard already resolved, and the Laravel session |
| Before each queued job (not `sync`) | the same                                                                       |

Octane and the queue worker forget the container's scoped instances themselves at each boundary. The full reset, as a
worker starts and whenever `Iam::resetWorkerState()` is called, also forgets the members' scoped request state
(`laravel-authentication`'s, SSO's and `laravel-authorization`'s: its resolved tenant, its resolution cache's memo and
its last decision among them), this package's own scoped adapters and records (those
scoped under the `iam.scoped:` prefix), and the facade roots that would keep them, so a long-running command that
resets between tenants keeps none of the suite's decisions about the first tenant. It forgets only the suite's scoped
state: a scoped binding your application made, over a seam or of its own, is kept, so a loop of your own forgets those
with the container's `forgetScopedInstances()` (below). It keeps Laravel's `Context`, its deferred callbacks,
audit-log's execution frames and the caller a queued job carried (`Iam\Audit\JobCallers`), which is frame state as
audit-log's frames are: the queue worker and Octane forget it at their own boundaries, and a reset called by hand
inside a job keeps it, so the job's later records, and the jobs it dispatches, still name the caller who dispatched
it.

- **Octane.** Keep Octane's default listeners. Under Octane every listener and scoped record this package uses
  resolves from the request's sandbox, so nothing reaches another request. Leave the members' services out of
  `octane.warm`, and register authentication context contributors only in a provider's `boot()` (see
  `laravel-authentication`'s [operations guide][auth-long-running]).
- **Queue workers.** A job on the `sync` connection runs inside the request that dispatched it, which owns that state,
  so it is skipped. A queued job carries the caller who dispatched it for the audit trail (see
  [The audit trail](audit-trail.md#who-did-it)).
- **Any other long-lived process.** A loop of your own (a consumer of another queue, a daemon) calls the reset between
  its units of work, and forgets the container's scoped instances itself, as Octane and the queue worker do, so a
  scoped binding of your own (an adapter you bound in a seam's place among them) keeps nothing of one unit for the
  next:

  ```php
  use SineMacula\Laravel\Iam\Facades\Iam;

  foreach ($messages as $message) {
      $handler->handle($message);

      Iam::resetWorkerState();
      app()->forgetScopedInstances();
  }
  ```

Turn `iam.workers.reset` off only when the application performs the same reset itself. How the reset is built is in
the [long-running processes design note](../design/long-running-processes.md).

[auth-operations]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/operations.md
[auth-pruning]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/operations.md#pruning
[auth-key-rotation]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/operations.md#key-rotation
[auth-per-guard-jwt]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/configuration.md#per-guard-jwt-configuration
[auth-long-running]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/operations.md#long-running-processes
[mfa-operations]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/operations.md
[mfa-secrets]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/secrets.md#rotating-the-application-key
[sso-operations]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/operations.md
[sso-several-servers]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/operations.md#several-servers-and-the-cache
[sso-long-running]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/long-running-processes.md
[sso-keys]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/keys.md
[sso-secrets]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/secrets.md#rotating-app_key
[audit-operations]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/operations.md
[audit-keys]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/operations.md#keys-and-their-lifetimes
