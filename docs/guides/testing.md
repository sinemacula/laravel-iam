# Testing

Helpers for testing an application that uses the suite: acting as a caller across every member in one call, fakes of
the contracts your application implements for this package, and contract kits that prove your own implementations.
Every class name below is relative to `SineMacula\Laravel\Iam\Testing` unless it says otherwise. Not one of them is for
production use.

The members' own helpers are in their guides: [laravel-authentication][authentication-testing],
[laravel-mfa][mfa-testing] and [laravel-sso][sso-testing]. Where this package changes how one of them behaves, this
guide says so.

- [Acting as a caller](#acting-as-a-caller)
- [Verifying a session you already hold](#verifying-a-session-you-already-hold)
- [Fakes](#fakes)
- [Contract kits](#contract-kits)

## Acting as a caller

`Concerns\InteractsWithIam::actingAsCaller()` arranges a whole caller from plain values: the identity, the principal,
the active tenant, the session, the level MFA verified it at and, for a session through SSO, SSO's provenance. Every
request the test then sends through the HTTP kernel is authenticated as that caller, until the test acts again or stops
acting.

```php
use SineMacula\Laravel\Iam\Testing\CallerSession;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;

final class InvoicesTest extends TestCase
{
    use InteractsWithIam;

    public function testAVerifiedMemberSeesTheTenantsInvoices(): void
    {
        $this->actingAsCaller(
            $user,
            tenant: 'tenant-1',
            session: CallerSession::signedIn(['email' => $user->email, 'password' => 'password']),
            verified: AssuranceLevel::AAL2,
        )->getJson('/api/invoices')->assertOk();
    }
}
```

A person is signed in for real, through `laravel-authentication`'s session service, as your application signs people
in, and the test acts on the new session. So every adapter reads the caller from the session `laravel-authentication`
wrote, exactly as it reads a real caller's: MFA's route gate, MFA's active tenant, the tenant authentication policy and
the `mfa` and `sso` context namespaces among them, so a session verified at a level reads `mfa.accepted` and
`mfa.level` in `Auth::context()`. Nothing is stubbed.

| Argument     | What it is                                                                                                      |
|--------------|-----------------------------------------------------------------------------------------------------------------|
| `$identity`  | The identity to act as: a person, or a machine (`SineMacula\Laravel\Authentication\Contracts\MachineIdentity`). |
| `$principal` | The principal to act as; the identity's default one when none is given.                                         |
| `$tenant`    | The id of the tenant to act in, a string or an integer; the principal's default when none is given.             |
| `$guard`     | The guard to act on; the default guard when none is given. It becomes the default guard.                        |
| `$session`   | How a person's session is signed in: a `CallerSession`, `CallerSession::started()` when none is given.          |
| `$verified`  | The level MFA verifies the session at, a `SineMacula\Laravel\Mfa\Enums\AssuranceLevel`; none when not given.    |
| `$scopes`    | A machine's scopes; none, `[]`, when not given.                                                                 |

### The session

`CallerSession` says how the person signs in, and so what the session's first factor is:

- `CallerSession::started($method = 'password')` starts the session as `laravel-authentication`'s `start()` does for an
  identity your application verified itself. Its first proof names the method, but no channel, so MFA can judge no
  first factor and no level can be verified after it. Use it for a test that needs a session and no MFA state.
- `CallerSession::signedIn($credentials, $method = 'password')` signs in with the credentials, as a sign-in endpoint
  does, so the first factor is the one the method proves (the password's, say). The credentials must sign in the very
  identity given. They are held wrapped, so a dump or a stack trace never shows them.
- `CallerSession::throughSso($provenance)` signs in through SSO, as `Iam::signIns()` signs in a person whose redemption
  SSO admitted, under `external_provider`. `$provenance` is SSO's own
  `SineMacula\Laravel\Sso\Sessions\Provenance`, and must name its link: under this package every SSO session is
  established through one. The session records the provenance's connection and link, and the provenance as its
  provider context, so `Auth::context()->get('sso.connection')` and the rest of the `sso.*` keys answer it
  ([laravel-sso: session provenance][sso-provenance]).

```php
use SineMacula\Laravel\Sso\Sessions\Provenance;

$this->actingAsCaller($user, session: CallerSession::throughSso(new Provenance(
    connectionId: 'connection-1',
    tenantId: 'tenant-1',
    protocol: 'oidc',
    methods: ['pwd', 'mfa'],
    linkId: 'link-1',
)));
```

The guard must allow the session's method (`external_provider`, through SSO), and the sign-in must activate the
identity acted as. One refused, still pending, or signed in as another identity, throws a `LogicException` naming the
reason, and whatever it wrote is rolled back, so a test never acts on, or leaves behind, a session it did not mean to.

### A person who already holds a factor

Under an application that requires a further factor of a person who holds one (`mfa.applications.<guard>.requirement` of
`enrolled` or `always`), the sign-in of a person who already holds a confirmed factor is left pending on that factor.
That person may be one your test seeded with a factor, or one an earlier `actingAsCaller()` call verified a level for,
since `$verified` leaves the person holding the factor it proved with. The helper completes the sign-in as the person
would, by verifying a factor: it makes a proof of the level's evidence (see [The level](#the-level); an authenticator
app's when no level is given) with a confirmed factor of that type the person holds, or with one it enrols for them when
they hold none, and hands it to MFA's pending completion, which `laravel-authentication` records on the session. So the
same person can be acted as again, verified again, in another tenant or at another level:

```php
$password = CallerSession::signedIn(['email' => $user->email, 'password' => 'password']);

$this->actingAsCaller($user, tenant: 'tenant-1', session: $password, verified: AssuranceLevel::AAL2);

// The person now holds an authenticator app, so this sign-in is left pending, and completed with it.
$this->actingAsCaller($user, tenant: 'tenant-2', session: $password, verified: AssuranceLevel::AAL2);
```

Without a level, the session then holds the first factor and the proof that completed the sign-in, so MFA's route gate
may already let it through a level. This needs a first factor MFA can judge: a session `CallerSession::signedIn()` or
`CallerSession::throughSso()`. A session `CallerSession::started()` holds none, so MFA accepts no further proof after
it, and acting as a holder on one throws a `LogicException` that says so (`The caller did not sign in on guard [api]:
[pending: mfa]. A started session holds no first factor MFA can judge, ...`). A sign-in still pending after the helper's
proof, on a choice of principal say, throws one naming what it waits on (`[pending: principal]`).

### The tenant

The tenant is chosen at sign-in, so the session records it, and MFA's active tenant, which reads only the validated
session, answers it. The test then acts in it, so `Auth::tenant()` answers it too. Your application's tenant resolver
and tenant access (`laravel-authentication`'s `TenantResolver` and `TenantAccess`) must admit it. For a person, a tenant
the resolver does not resolve, or tenant access refuses, fails the sign-in: a `LogicException` names the reason
(`The caller did not sign in on guard [api]: [tenant_ineligible].`), and everything the sign-in wrote is rolled back.
A tenant named with `$tenant` must be resolvable by `laravel-authentication`'s `TenantResolver` even when it is the
principal's own tenant, which `laravel-authentication` admits at sign-in without asking a resolver: the helper then
acts in the tenant it resolves, so under the default `ResolveNoTenant` it throws
`SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException` once the person has signed in. Leave `$tenant` out
to act in the principal's own tenant without a resolver. A machine, which signs in to no session, throws the same
exception when the resolver does not resolve the tenant.

### The level

With `$verified`, the session is stepped up the way a real step-up does it: a proof is made with a confirmed factor of
the level's kind the person holds, or with one enrolled for them when they hold none, and recorded by
`laravel-authentication` on the session. The person keeps the factor, so a later call for the same person uses it
again ([A person who already holds a factor](#a-person-who-already-holds-a-factor)). The proofs
are then read back as MFA's route gate reads them, and must reach exactly the level asked for, with additional
verification, or a `LogicException` names what was reached and what is unmet.

| Level  | The factor proved (and enrolled when the person holds none)                                           |
|--------|-------------------------------------------------------------------------------------------------------|
| `AAL1` | An email factor, with a code to a synthetic address                                                   |
| `AAL2` | An authenticator app                                                                                  |
| `AAL3` | A hardware-protected, phishing-resistant passkey, which needs a combination policy that rates it AAL3 |

The further proof is made now, so a test of freshness verifies the session and then moves the clock on
(`$this->travel(20)->minutes()`). A level needs a first factor MFA can judge: a session `CallerSession::signedIn()` or
`CallerSession::throughSso()`. `CallerSession::started()` is refused with an `InvalidArgumentException` before anything
is signed in, as is `AssuranceLevel::UNCLASSIFIED`.

Through SSO, MFA's default combination policy classifies the provider's first factor at no level, so under it
`$verified` can reach none of AAL1, AAL2 or AAL3: the email code AAL1 proves is unclassified on its own (`Requested aal1
with additional verification; reached unclassified; unmet: minimum_level.`), the authenticator app AAL2 proves reaches
only AAL1, and AAL3 needs a policy that rates a passkey AAL3. A test that verifies a level through SSO binds the
combination policy your application binds, one that rates the further proof the level asks for on its own, as
`Tests\Fixtures\Testing\LeveledCombinationPolicy` does for AAL3 in this package's own tests. The fixture session
carries no evidence SSO's evidence contract accepted, so a policy that trusts the connection's `external_provider` first
factor never sees the connection through it ([MFA and SSO](mfa-and-sso.md#what-accepted-evidence-reaches)).

### A machine

A machine identity signs in to no session: the test acts as it, as `laravel-authentication`'s `actingAsIdentity()`
does, limited to the scopes given, and in the tenant given. A session or a level for a machine, and scopes for a
person, throw an `InvalidArgumentException` before anything is written.

```php
$this->actingAsCaller($client, guard: 'machines', scopes: ['invoices:read'])
    ->getJson('/api/invoices')
    ->assertOk();
```

### Asserting what is bound

`InteractsWithIam` brings in `laravel-authentication`'s `InteractsWithAuthenticationContext`, so its assertions and
helpers are there too: `assertBoundIdentity()`, `assertBoundPrincipal()`, `assertBoundTenant()`,
`assertBoundSession()`, `assertBoundScopes()` and `stopActing()`.

### MFA's own helper

MFA's `InteractsWithMfa::actingAsVerified()` records synthetic proofs through MFA's proof store. Under this package the
proof store is `laravel-authentication`'s sessions, which only `laravel-authentication` writes, so the helper is refused
with MFA's `ProofRefusedException`. Use `$verified` instead. MFA's other helpers, such as
`SineMacula\Laravel\Mfa\Testing\AuthenticatorApp`, work as MFA's guide describes.

## Verifying a session you already hold

`actingOnVerifiedSession($session, $level = AssuranceLevel::AAL2, $guard = null)` acts on a session your test signed
in itself, as `actingOnSession()` does, and verifies it at exactly the level, as `$verified` does. The session must be a
live, active session of a person, holding a first factor MFA can judge.

```php
$this->actingOnVerifiedSession($session, AssuranceLevel::AAL2)->getJson('/api/account')->assertOk();
```

## Fakes

Each fake implements one of the contracts your application implements for this package. `fake()` binds a fresh
instance in the container and returns it.

### Gateways

`FakeEmailGateway` and `FakeSmsGateway` keep every `SineMacula\Laravel\Iam\Delivery\CodeMessage` they are handed
instead of delivering it, whichever member issued the code. Name the fake in `iam.delivery.email` or `iam.delivery.sms`
before the application boots, so the members' senders are pointed at it, then call `fake()` in the test. Use them
rather than MFA's own `FakeEmailSender` and `FakeSmsSender`, and rather than `laravel-authentication`'s
`SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender`, which that member's testing guide suggests: binding
one of MFA's fakes replaces this package's sender, so MFA's codes stop reaching your gateway, and binding
`FakeOneTimeCodeSender::fake()` replaces this package's one-time code sender, so both members' codes, MFA's email and
SMS codes among them, stop reaching it. Either way the codes take another path than they take in production.

```php
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;

$mailbox = FakeEmailGateway::fake();

$this->postJson('/mfa/send', ['factor' => $factor->id])->assertOk();

$code = $mailbox->lastCodeTo('person@example.test');
```

| Method                                      | What it does                                                 |
|---------------------------------------------|--------------------------------------------------------------|
| `sent($filter = null)`                      | Every message, oldest first, or those the closure accepts    |
| `sentTo($destination)`                      | The messages to the address or phone number                  |
| `lastCodeTo($destination, $purpose = null)` | The code last sent there, for the purpose given or any       |
| `failNext($exception = null)`               | Makes the next delivery throw, as a provider's failure would |
| `reset()`                                   | Forgets every message so far                                 |

A code `laravel-authentication` issues arrives when its queued delivery job runs, so run the queue synchronously in
tests that read one.

### Memberships, the tree and the tenant requirement

| Fake                       | Contract                                                | What the test tells it                                                                                         |
|----------------------------|---------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| `FakeMemberships`          | `SineMacula\Laravel\Iam\Contracts\Memberships`          | `grant($identity, $membership)`, `revoke($identity, $tenantId)`, `incomplete($identity)`, `failFor($identity)` |
| `FakeTenantTree`           | `SineMacula\Laravel\Iam\Contracts\TenantTree`           | `place($tenantId, $parentId = null)`, `remove($tenantId)`, `failFor($tenantId)`                                |
| `FakeTenantMfaRequirement` | `SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement` | `require($tenantId, $requirement)`, `requireNothing($tenantId)`, `failFor($tenantId)`                          |

Each keeps what it was asked (`asked()`). Name `FakeMemberships` in `iam.tenancy.memberships`, or `FakeTenantTree` in
`iam.tenancy.tree`, before the application boots, as well as calling `fake()`: bound only from the test, either is the
one asked, but no SSO adapter is bound over SSO's defaults for it. A tenant MFA requirement bound in the container counts
as named whenever it is bound.

```php
use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;

FakeMemberships::fake()->grant($user, Membership::of('tenant-1', CarbonImmutable::now()->subDay()));

FakeTenantMfaRequirement::fake()->require('tenant-1', new Requirement(multifactor: new RequirementPart(300)));
```

Change a tenant's requirement or move a tenant before the sessions it concerns are judged, or report the change after
(`Iam::tenantPolicies()->changed()`, `Iam::treeChanges()->changed()`), as your application would. A faked tenant MFA requirement
needs a tenant resolver in the test as in the application: bind your application's `TenantResolver`, or MFA's route
gate throws `UnresolvedReferenceException` for a session in a tenant (see
[Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-resolver)).

### The provisioner

`FakeProvisioner::fake($create, $member = null)` makes each identity with the closure given, which inserts one of your
own identity models, and keeps each membership, written by the second closure when one is given. Provisioning is on
from then. `refuseIdentities()` and `refuseMemberships()` make it refuse, and `identities()` and `memberships()` answer
what it made, whether or not the provisioning then committed: read the rows to see what a rollback undid.

```php
use SineMacula\Laravel\Iam\Testing\FakeProvisioner;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

$provisioner = FakeProvisioner::fake(fn (VerifiedResult $result): User => User::query()->create([
    'email' => $result->linkingEmail?->email,
]));
```

### The group mapping

`FakeGroupMapping::fake()` binds a mapping that maps each group to what you tell it, and any other group to nothing:
a role's name, granted in the connection's tenant alone, or a `GrantInstruction`. `refuse()` makes every question
throw, and `asked()` answers each connection, tenant and list of groups it was asked about.

```php
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;

FakeGroupMapping::fake()
    ->map('finance', 'invoices.viewer')
    ->map('finance-admins', GrantInstruction::roleWithSubtree('invoices.approver'));
```

## Contract kits

Each kit is a trait of PHPUnit tests that proves an implementation of one of this package's contracts keeps its
promises. Use it in a test case of your own and implement its hooks against your implementation. The fakes above pass
their kits. Each kit's checks are static assertions on the `Seams\*Contract` class beside its trait
(`Seams\MembershipsContract`, `Seams\TenantTreeContract`, `Seams\TenantMfaRequirementContract`,
`Seams\ProvisionerContract`, `Seams\GroupMappingContract`, and `Seams\EmailGatewayContract` and
`Seams\SmsGatewayContract`, which share `Seams\GatewayContract`'s), so a test can call one directly, such as
`Seams\MembershipsContract::assertNeverCompleteWhenUnreadable()`.

| Kit                                        | Proves                      | Hooks                                                                                                                                                                                                                                     |
|--------------------------------------------|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Seams\Concerns\EmailGatewayTests`         | Your `EmailGateway`         | `codeGateway()`, `codeApplication()`, `codeRecipient()`, `codesDeliveredTo()`, `failCodeDelivery()`                                                                                                                                       |
| `Seams\Concerns\SmsGatewayTests`           | Your `SmsGateway`           | The same as the email kit                                                                                                                                                                                                                 |
| `Seams\Concerns\MembershipsTests`          | Your `Memberships`          | `memberships()`, `memberIdentity()`, `membershipTenant()`, `membershipAcceptedAt()`, `invitedIdentity()`, `revokeMembership()`, `partlyReadableIdentity()`, `widelyHeldIdentity()`, `otherMembershipTenant()`, `holdsPlatformPrincipal()` |
| `Seams\Concerns\TenantTreeTests`           | Your `TenantTree`           | `tenantTree()`, `treeLeaf()`, `treeLeafAncestors()`, `treeOutsider()`, `treeRootDescendants()`                                                                                                                                            |
| `Seams\Concerns\TenantMfaRequirementTests` | Your `TenantMfaRequirement` | `tenantMfaRequirement()`, `tenantMfaTenant()`, `tenantMfaApplication()`, `changeTenantMfaRequirement()`, `unanswerableTenant()`                                                                                                           |
| `Seams\Concerns\ProvisionerTests`          | Your `Provisioner`          | `provisioner()`, `provisionedResult()`, `existingIdentity()`, `resultMatching()`, `declinedResult()`, `isMemberOf()`                                                                                                                      |
| `Seams\Concerns\GroupMappingTests`         | Your `GroupMapping`         | `groupMapping()`, `connectionId()`, `tenantId()`, `mappedGroups()`, `unmappedGroups()`, `expectedGrants()`, `declinedQuestion()`                                                                                                          |

```php
use App\Tenancy\DatabaseTenantTree;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\TenantTreeTests;

final class DatabaseTenantTreeTest extends TestCase
{
    use TenantTreeTests;

    protected function tenantTree(): TenantTree
    {
        return new DatabaseTenantTree;
    }

    // treeLeaf(), treeLeafAncestors(), treeOutsider() and treeRootDescendants() name the tenants your test seeded.
}
```

The gateway kits read the application's log, so a test case using one must not fake the log's `MessageLogged` event
(as `Event::fake()` with no list does). A contract of MFA's that you bind yourself in place of one of this package's
adapters (see [Bindings](bindings.md)) is proved with MFA's own kit for it, under
`SineMacula\Laravel\Mfa\Testing\Seams\Concerns` ([laravel-mfa: testing][mfa-testing]); this package's own tests run
those kits against its adapters. `laravel-authentication` and SSO ship no contract kits, so an implementation of one
of their contracts is proved by tests of your own against that member's guide.

[authentication-testing]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/testing.md
[mfa-testing]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/testing.md
[sso-provenance]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/session-provenance.md
[sso-testing]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/testing.md
