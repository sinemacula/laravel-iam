# Tenant Authentication Policy

## Purpose

This note describes how the package answers `laravel-authentication`'s tenant authentication policy (IAM-4.5,
AUTH-2.12) from SSO's enforcement, SSO's exemption gate and the application's implementation of laravel-mfa's
`TenantRequirement` (MFA-10.2). It covers how the policy's answer and its version are composed, which reads it makes and
on which connection, when the exemption gate is asked, how an enforcement change and a changed requirement reach
existing sessions, and the gaps in the members the adapters work around. The redemptions and SSO's revocation scopes
are in `sso-redemption-and-revocation.md`, and the binding rule that applies every row in `binding-precedence.md`.

## Invariants

- Which tenants require which further factors is the application's own data. The application implements laravel-mfa's
  `TenantRequirement::requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant)` and
  binds it; MFA asks it itself, and the package reads the same binding into the tenant policy
  (`Tenancy\TenantMfaRequirements`), so the two members never disagree. A requirement is in use while MFA's tenant
  requirement resolves to something other than MFA's `NoTenantRequirement` (`isConfigured()`); with MFA's default, no
  tenant requires a further factor and nothing is asked. The application tests its own with MFA's
  `TenantRequirementTests` kit.
- The requirement answers for exactly the tenant asked: the package applies no inheritance down a tenant tree (Decision
  Q6 (a)), and a move the application reports (`Iam::treeChanges()->changed($tenantId)`) judges the moved tenant's
  subtree against what the requirement then answers (Decision Q7, `provisioning-and-tenancy.md`). The policy asks it
  inside `WriteConnection::during()` for the tenant, with the tenant's identifier as a string, resolved from the
  container on every call, and translates its answer part by part (`RequirementTranslator::toAuthentication()`).
  Whatever it throws propagates. MFA's contract types the identity as `MultiFactorAuthenticatable`, so once a
  requirement is bound an identity that is not one throws `UnresolvedReferenceException::forMfaIdentity()`, never an
  empty answer.
- The seam, and the default it replaces:

  | Member seam                       | Bound to                                    | Member default replaced   | Lifetime  | Switch             |
  | --------------------------------- | ------------------------------------------- | ------------------------- | --------- | ------------------ |
  | AUTH `TenantAuthenticationPolicy` | `Tenancy\TenantAuthenticationPolicyAdapter` | `RequireNothingOfTenants` | transient | `iam.adapters.sso` |

  The policy's row is declared in `Tenancy\TenancySeams`, apart from either capability, since it composes both. It is
  bound while `iam.adapters.sso` is on, whatever `iam.adapters.mfa` says: it composes SSO's enforcement and exemption
  gate, and hands the gate the client of the redemption this package's SSO capability admitted in the request
  (`AdmittedRedemptions`), which nothing records with that capability off. It is mandatory while SSO's
  `sso.features.enforcement` is on or MFA's tenant requirement is bound off its default, a mandate `iam:check` reads
  from the row (`Checks\MandatorySeamsCheck`): left on the default then, no tenant's enforcement or requirement would
  reach a session. It is bound whatever those say, since either may be turned on while the application runs. With
  `iam.adapters.sso` off the policy is the application's to bind, beside the SSO seams it binds, as a mandatory one
  under the same conditions. The packaged configuration says so (`config/iam.php`, `adapters` and `tenancy`).
- The policy's answer, on every call and with nothing cached (`TenantAuthenticationPolicyAdapter::requirementFor()`):
  1. SSO's `Enforcement::policy($tenantId, $application)`, the tenant named by its identifier as a string and the
     application by the guard; with the `enforcement` feature off it reads nothing;
  2. where the rule is required and the session (or the sign-in) was not established through one of its satisfying
     connections, SSO's `ExemptionGate::admit()`, the only place the exemption is asked;
  3. MFA's tenant requirement for the identity, the application and the tenant.

  The connections are the rule's satisfying connections, unless the rule requires none (`null`) or the identity is
  exempt (`null`); a rule whose every connection has gone requires `[]`, which none satisfies. The further factor is
  MFA's tenant requirement, translated.
- The version (`Tenancy\TenantPolicyVersion::of()`) is the SHA-256 digest, in hexadecimal (64 characters), of every
  input in one canonical form: SSO's policy as it serialises itself (the tenant, the enforcing tenant, whether a
  connection is required, the satisfying connections in id order, the rule's version), the exemption's outcome where
  the gate was asked, and the requirement part by part. SSO's own version changes only with the enforcing tenant's
  rule, not when a satisfying connection is disabled, and an exemption has no version, so the digest is what changes
  whenever anything the answer depends on does.
- The connection a session, or a sign-in, was established through is the one `laravel-authentication` names to the
  policy (`TenantPolicyContext::connectionId()`), asked only once the rule requires a connection, so a tenant with
  nothing enforced costs no read of the session's provenance. `laravel-authentication` finds it once for the policy
  and its own judgement alike: a sign-in's from its evidence in memory, before its session is written, and a
  session's from its recorded provenance on the write connection, pending sessions included, read current where it
  holds the session's row locked (a refresh, a switch, an external re-authentication, `tenantPolicyChanged()`): on
  MySQL at REPEATABLE READ a plain read answers from the transaction's snapshot, which may be older than the session
  its locking read found, so a session committed after that snapshot (an SSO sign-in committing while an enforcement
  change's transaction has read and not yet revoked) would otherwise be taken for one through no connection. The
  policy asks for it while it answers, never after, as the context requires. So the gate is asked only for a session
  the rule would refuse, and an exempt identity's compliant session reports no exemption.
- The policy only reads, and takes no lock of its own. The current read of the provenance is
  `laravel-authentication`'s, whose shared lock of the session's provenance row on MySQL and MariaDB comes after the
  session's row in its own order (the session's row, then its proofs), so nothing the policy does can invert the
  order that ends with the session's row.
- No request is read. `laravel-authentication` hands the policy no client. Where the judgement is that of a sign-in or a
  re-authentication this package redeems, the gate is handed the client of that redemption, the one SSO was handed for
  its admission and `AdmittedRedemptions` keeps with it (`clientFor()`): it answers only for the identity the
  redemption links and the session it names, none for a sign-in, so it is the client of the request being judged and an
  `ExemptionUsed` the gate reports carries that request's IP address and user agent, as SSO's guide asks. Every other
  judgement (a refresh, a switch, `tenantPolicyChanged()`, a password or passkey sign-in) hands the gate SSO's
  `new ClientContext(null, null)`, as a job's is: an `ExemptionUsed` it reports then carries no IP address or user
  agent.
  The identity is named to SSO through the morph map (`Sso\IdentityReferences`); a tenant whose identifier is neither a
  non-empty string nor an integer throws `UnresolvedReferenceException::forTenantIdentifier()` inside the caller's
  transaction (IAM-8.2).

## Success Path

1. A password sign-in in a tenant with SSO's enforcement off and MFA's default tenant requirement: the policy reads
   nothing and answers no requirement at a version of its own; the session records it.
2. A sign-in through SSO in an enforcing tenant: SSO's redemption locks the enforcing tenant's rule and admits the
   connection; `signInExternally()` asks the policy, which reads the rule and its connections, is told the sign-in's
   connection from its evidence, asks no exemption, and answers the connections, the
   requirement and the version. The session's provenance names the enforcement version SSO judged under its locks
   (`policy_version`, and `sso.enforcement_version` in the provider context), and the session records the policy's
   own version as its `tenant_policy_version`.
3. A refresh of that session: the policy reads the rule and its connections, and asks for the session's recorded
   connection, which `laravel-authentication` reads once for the policy and its own judgement, and answers as before;
   `laravel-authentication` judges the session and keeps it.
4. An enforcement change (`EnforcementService::update()`): SSO calls the session revocation inside its transaction,
   which calls `tenantPolicyChanged($tenant)` (IAM-4.4) for the enforcing tenant and, with the application's tenant tree
   configured, for every tenant below it (`provisioning-and-tenancy.md`), whose policy SSO's enforcement inheritance
   answers from the nearest tenant up that has a rule, on or off; `laravel-authentication` locks the tenant's sessions
   committed by then and asks the policy for each. A session through a satisfying connection meets it, an exempt
   identity's session is answered with no connection (and its exemption reported once the change commits), and every
   other active session it locked is revoked in the change's transaction, whatever any setting says. Once the change
   commits, the revocation calls `tenantPolicyChanged($tenant)` a second time, as `laravel-authentication` asks for a
   strict cut-off: every session the first pass recorded at the version it answered is skipped, and a session that
   entered the tenant while the first pass ran (a password or passkey sign-in, a switch into the tenant, a sign-in
   through another tenant's connection, none of which takes SSO's lock of the rule) is judged and, falling short,
   revoked (`sso-redemption-and-revocation.md`). Both passes go through `Tenancy\SubtreePolicyChanges::changed()`,
   whose pass after the commit lists the enforcing tenant's subtree again (`provisioning-and-tenancy.md`). The
   second pass runs only once every callback queued on the change's transaction has run, so SSO reports the change
   (`EnforcementChanged`) once, before it; what the second pass throws propagates from `EnforcementService::update()`
   once the change is durable and reported, its first pass's revocations standing. A commit callback that fails, before
   it or after it (a synchronous listener of `EnforcementChanged`), leaves the change durable and the second pass held
   until the request, the command or the job ends, where it runs (`AfterConnectionCommits::settle()`).
5. A changed tenant requirement: the application changes its data and, inside the transaction that publishes the
   change, on the storage connection (`Iam::transaction()` opens one), reports it with
   `Iam::tenantPolicies()->changed($tenant)`. That is `laravel-authentication`'s strict cut-off: the first
   `tenantPolicyChanged($tenant)` runs there, as a savepoint, so it commits or rolls back with the change, and judges
   every session committed by then; the version changed with the answer, so each is judged again, and one without the
   further factor is revoked. A sign-in into the tenant that read the requirement before the change committed (from its
   snapshot on MySQL at REPEATABLE READ, at READ COMMITTED before the commit) and commits its session after the first
   pass locked the tenant's sessions is not among them, so a second `tenantPolicyChanged($tenant)` runs once the
   transaction commits, as for an enforcement change, and revokes it; the change rolled back runs none. An application
   that calls `Auth::sessions()->tenantPolicyChanged($tenant)` itself makes the same two calls, the first inside that
   transaction and the second after it commits: one call alone leaves such a session acting on its access tokens until
   they expire, since bearer requests never recheck the tenant's policy. MFA, asked for the session's requirement,
   composes the same requirement once the session acts in the tenant.
6. A changed exemption: the application's `EnforcementExemption` is its own data, which neither SSO nor this package
   watches, so whenever its answer changes for an identity (a grant or a withdrawal) the application reports the change
   the same way, `Iam::tenantPolicies()->changed($tenant)` inside the transaction that publishes it, for every tenant
   whose enforcement the identity was, or is now, exempted from. The gate's outcome is part of the version, so the
   identity's sessions there are judged again at once and once more after the commit: a withdrawn exemption's password
   session is revoked, one that entered the tenant while the first pass ran included, and a granted one's is recorded
   at the new version.

## Failure / Edge Cases

- A password sign-in in an enforcing tenant is refused as `sso_required`, with no session and no pending continuation,
  unless the identity is exempt.
- Turning a rule off revokes nothing: SSO calls no revocation then, and the policy answers no connection. With the
  application's tenant tree configured this still holds: a rule turned off is still its tenant's rule, so the tenant and
  every tenant inheriting from it stay on it, never moving onto a stricter ancestor's rule
  (`provisioning-and-tenancy.md`).
- An exemption withdrawn, or a requirement changed, without a report leaves the sessions in the tenant standing: bearer
  requests never recheck the tenant's policy, so they keep acting on their access tokens until those expire, and are
  refused only at their next refresh. Nothing in SSO or this package starts that judgement. A report made with one
  `tenantPolicyChanged()` call alone misses a session that entered the tenant while the call ran, the same way.
- With `iam.adapters.sso` off the policy is not bound: an application binding SSO's seams itself binds the policy too,
  since only this package's SSO capability records the redemption whose client the gate is handed.
- An exempt identity signing in, or re-authenticating, through another tenant's connection to act in an enforcing
  tenant whose rule does not list it (SSO judges the redemption against the connection's tenant's rule alone) is
  admitted by the gate, and the `ExemptionUsed` it reports carries the IP address and user agent the redemption was
  made for; a later judgement of that session (a refresh, a reported change) reports it with no client.
- Each pass of an enforcement change asks the policy for an exempt identity's session (the second to learn the version
  it skips), and so the gate, which reports `ExemptionUsed` each time it grants: the exemption is reported once by
  each pass.
- A session acting in another tenant is never judged by a tenant's change.
- Inside a transaction that has already read, on MySQL at REPEATABLE READ, SSO's `policy()` answers as of the
  transaction's snapshot. A redemption's sign-in is judged by SSO against the rule it locked, as it is now, and named on
  the provenance at that rule's version; were the rule changed between the redemption's first read and SSO's lock, the
  policy's answer would be the older rule's, so it could only refuse what SSO admitted (`sso_required`, rolled back, the
  code left unspent) or record a version the next judgement does not skip, never admit what SSO refused. The change's
  own revocation, which waited on SSO's lock, judges every session as the rule then is.
- On MySQL at REPEATABLE READ, an enforcement change whose transaction read before a sign-in through SSO committed,
  and whose first pass then finds that session through `laravel-authentication`'s locking reads, judges it by its
  provenance read current, never from the change's older snapshot, which holds no provenance row for it: a session
  through a satisfying connection is answered as compliant, the gate is not asked, no `ExemptionUsed` is reported for
  an exempt identity, and the version it records is the one the next judgement answers. At READ COMMITTED each
  statement reads what is committed, and on PostgreSQL at REPEATABLE READ the locking read never finds a session
  committed after the snapshot (the second pass judges it), so there a plain read would agree with the locking one.
- A tenant requirement that cannot answer for a tenant throws, and the sign-in, refresh or change fails rather than
  proceed as though nothing were required; so does an identity that is not `MultiFactorAuthenticatable` once a
  requirement is bound.
- Gaps in the members the adapters work around:
  - `laravel-authentication`'s `TenantPolicyContext` carries no `ClientContext`, though every caller of the policy
    holds one. A sign-in or a re-authentication this package redeems hands the gate the client it keeps with the
    admitted redemption, but where `laravel-authentication` alone holds the client (a refresh, a switch, a password or
    passkey sign-in, and `tenantPolicyChanged()`, which judges stored sessions for no request), SSO's `ExemptionUsed`
    carries none.
  - `laravel-sso`'s `EnforcementPolicy::$version` does not change when a satisfying connection is disabled, and an
    exemption has no version (`EnforcementExemption`), so the adapter versions SSO's whole serialised policy and the
    gate's outcome rather than SSO's version alone.
  - Neither member ships a contract kit for `TenantAuthenticationPolicy`.
  - laravel-mfa offers no public way to tell its own default binding from the application's, so a requirement is in use
    while the binding does not resolve to `NoTenantRequirement`; it switches to `MfaServiceProvider::isPackageDefault()`
    once laravel-mfa ships it.

## Implementation Anchors

- `src/Tenancy/TenantMfaRequirements.php`: `requirementFor()`, `isConfigured()`;
  `src/Mfa/Translation/RequirementTranslator.php`: `toAuthentication()`.
- `src/Tenancy/TenantAuthenticationPolicyAdapter.php`: `requirementFor()`; `src/Tenancy/TenantPolicyVersion.php`:
  `of()`; `src/Sso/AdmittedRedemptions.php`: `clientFor()`, `record()`;
  `src/Sso/SignInRedemption.php`, `src/Sso/ReauthenticationRedemption.php`: `redeem()`, recording the client.
- `src/Tenancy/TenancySeams.php`: `seams()`, `isEnforcedOrRequired()`, `ENFORCEMENT`;
  `src/IamServiceProvider.php`: `seamProviders()`.
- `src/Tenancy/TenantPolicyChanges.php`: `changed()`; `src/IamManager.php`: `tenantPolicies()`; `src/Facades/Iam.php`;
  `src/Transactions/AfterConnectionCommits.php`: `run()`, `committed()`, `settle()`.
- `src/Exceptions/UnresolvedReferenceException.php`: `forTenantIdentifier()`, `forMfaIdentity()`.
- `benchmarks/Tenancy/TenantAuthenticationPolicyBench.php`, `benchmarks/Support/TenantAuthenticationPolicyBenchHarness.php`.

## Authoritative Tests

- `tests/Integration/Tenancy/TenantAuthenticationPolicyAdapterTest.php` (MySQL and PostgreSQL at READ COMMITTED and
  REPEATABLE READ for the lock) `testTheAdapterIsThePolicyBound`, `testWithNothingOnNothingIsRequiredAndNothingRead`,
  `testAnEnforcedTenantRequiresItsConnections`, `testASessionTheRuleWouldRefuseIsJudgedByTheGate`,
  `testAnExemptIdentitysSessionNeedsNoConnection`, `testAnExemptIdentitysCompliantSessionReportsNoExemption`,
  `testASignInThroughASatisfyingConnectionNeedsNoGate`, `testASignInThroughNoSatisfyingConnectionIsJudgedByTheGate`,
  `testTheConnectionIsAskedForOnlyWhenTheRuleRequiresOne`, `testARuleWithNoConnectionLeftIsSatisfiedByNone`,
  `testTheApplicationsRequirementIsTheFurtherFactor`, `testTheVersionChangesWhenAnyInputChanges`,
  `testTheApplicationsRequirementIsReadOnTheWriteConnection`, `testItTakesNoLockUnderTheSessionsLock`,
  `testItTakesNoLockOutsideATransaction`, `testATenantThatCannotBeNamedThrows`,
  `testAnIdentityMfaHoldsNoFactorsForIsRefusedOnceARequirementIsBound`; the locks are counted from the moment the
  session's own lock is taken, or the question asked outside a transaction (`Tests\Concerns\CountsLockingReads`)
- `tests/Integration/Tenancy/EnforcementThroughTenantPolicyTest.php` (every isolation level where it commits)
  `testASignInNamesTheEnforcementVersionJudgedUnderTheLocks`, `testAPasswordSignInInTheEnforcingTenantIsRefused`,
  `testAnExemptPersonSignsInWithAPassword`, `testAnExemptRedemptionReportsTheExemptionWithItsClient`,
  `testAnEnforcementChangeRevokesTheSessionsTheRuleNoLongerAllows`,
  `testAWithdrawnExemptionReportedAsAPolicyChangeRevokesTheExemptSession`, `testAnotherTenantsSessionsAreNotJudged`,
  `testATenantRequirementRevokesTheSessionsWithoutItsFactor`, `testAnUnchangedPolicyIsRecordedAsTheVersionAnswered`,
  `testASecondPassThatThrowsLeavesTheChangeDurableAndReported`,
  `testThePolicyTakesNoLockUnderTheSessionsLock` (MySQL and PostgreSQL at READ COMMITTED and
  REPEATABLE READ, SSO's own enforcement reading its stored rule and connections under the session's lock)
- `tests/Integration/Tenancy/CompliantSessionUnderAnOlderSnapshotTest.php` (MySQL and PostgreSQL at READ COMMITTED and
  REPEATABLE READ, an exempt person's sign-in through the rule's connection committed on another connection after the
  judging transaction read) `testACompliantSessionCommittedAfterTheSnapshotIsJudgedWithoutTheGate`
- `tests/Integration/Tenancy/EnforcementSecondPassTest.php` (MySQL and PostgreSQL at READ COMMITTED and REPEATABLE
  READ) `testASessionThatEnteredTheTenantDuringTheChangeIsRevokedOnceItCommits`
- `tests/Integration/Tenancy/RequirementChangeSecondPassTest.php` (MySQL and PostgreSQL at READ COMMITTED and
  REPEATABLE READ, the requirement read from the application's own table)
  `testASessionThatEnteredTheTenantDuringTheChangeIsRevokedOnceItCommits`;
  `tests/Integration/Tenancy/TenantPolicyChangesTest.php` `testInsideATransactionTheTenantIsJudgedNowAndOnceItCommits`,
  `testARolledBackChangeRunsNoSecondPass`, `testWithNoTransactionOpenBothPassesRunAtOnce`;
  `tests/Feature/IamManagerTest.php` `testTheTenantPolicyChangesAreReachedThroughTheirOwnService`
- `tests/Integration/Tenancy/EnforcementRaceTest.php` (MySQL and PostgreSQL at READ COMMITTED and REPEATABLE READ, the
  change committed on another connection after the redemption read its code and before it locked)
  `testARuleThatNoLongerAdmitsTheConnectionRefusesTheSignIn`,
  `testARuleThatStillAdmitsTheConnectionSignsInAndIsJudgedAsItIsNow`
- `tests/Feature/Tenancy/TenancySeamsTest.php` `testTheAdapterIsBoundOverTheDefaultInEveryProviderOrder`,
  `testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins`, `testBothSwitchesOffBindNothing`,
  `testMfaOnWithSsoOffBindsNothing`, `testTheBindingIsOnWhileTheSsoSwitchIs`, `testTheBindingIsTransientOverTheDefault`,
  `testTheBindingIsMandatoryWhileEnforcementIsOn`, `testARequirementBoundMakesTheBindingMandatory`;
  `tests/Feature/Bindings/AdaptersDocumentationTest.php` `testTheAdaptersSectionNamesEverySeamTheSwitchesBind`,
  `testTheAdaptersSectionSaysWhenTheTenantPolicyIsTheApplicationsToBind`,
  `testTheTenancySectionSaysTheRequirementIsMfasTenantRequirement`, `testTheTenancySectionAsksForTheStrictCutOff`
- `tests/Unit/Tenancy/TenantPolicyVersionTest.php` `testTheSameInputsGiveTheSameVersion`,
  `testAChangeToAnyInputGivesAnotherVersion`, `testAMinimumLevelsLevelAndAgeAreEachPartOfTheVersion`;
  `tests/Unit/Tenancy/TenantMfaRequirementsTest.php` `testARequirementIsConfiguredOnceBoundOffMfasDefault`,
  `testTheBindingIsAskedAndItsAnswerTranslated`, `testWithMfasDefaultNothingIsRequired`,
  `testAnIdentityMfaHoldsNoFactorsForIsRefused`; `tests/Unit/Sso/AdmittedRedemptionsTest.php`
  `testASignInsClientIsAnsweredForItsIdentityAndNoSessionAlone`,
  `testAReauthenticationsClientIsAnsweredForItsIdentityAndSessionAlone`, `testTheNextRedemptionAnswersItsOwnClient`
- `tests/Performance/Tenancy/TenantPolicyQueryBudgetTest.php` `testAPasswordSignInWithNothingOn`,
  `testALinkedSignInInAnEnforcingTenant`, `testARefreshWithNothingOn`, `testARefreshInAnEnforcingTenant`

## Change Triggers

Update this note when:

- `laravel-authentication` changes `TenantAuthenticationPolicy`, `TenantPolicyContext` or `TenantRequirement`, hands the
  policy a client (the gate is then handed it on every path, the admitted redemption's client is dropped, and the
  binding may then follow `iam.adapters.mfa` too), changes how a version is compared or recorded, or rechecks the
  policy as a session is written (the second pass of every policy change may then be dropped);
- SSO changes `Enforcement::policy()`, `EnforcementPolicy`, its version's meaning or `ExemptionGate::admit()`, or
  starts versioning or watching exemptions (the application's obligation to report a changed exemption then goes);
- MFA changes `TenantRequirement` or ships `MfaServiceProvider::isPackageDefault()`;
- a reported tree move (`Iam::treeChanges()`, `provisioning-and-tenancy.md`) stops judging the moved tenant's whole
  subtree through `SubtreePolicyChanges` while SSO's enforcement or a requirement is on (Decision Q7), or inheritance of
  a requirement down the tree is decided otherwise than Q6 (a);
- `iam:check` stops reading the policy's mandate from its row (`Checks\MandatorySeamsCheck`, `install-and-check.md`).
