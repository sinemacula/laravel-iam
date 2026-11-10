<?php

declare(strict_types = 1);

namespace Tests\Feature\Bindings;

use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use Tests\TestCase;

/**
 * Feature tests for what the packaged configuration tells an application about
 * the adapters' switches, which it may turn off only to bind every seam they
 * bind itself: the `adapters` section names every seam a capability that either
 * switch governs binds, the tenant authentication policy among them, and the
 * `tenancy` section says which switches the tenant MFA requirement reaches the
 * members through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class AdaptersDocumentationTest extends TestCase
{
    /** @var array<class-string, string> What the `adapters` section calls each seam the switches govern. */
    private const array NAMES = [
        AdditionalFactorPolicy::class         => 'the additional-factor requirement',
        AuthenticationRequirementCheck::class => 'the requirement check',
        PendingSessionResolver::class         => 'pending sessions',
        PendingCompletion::class              => 'pending sessions',
        StepUp::class                         => 'step-up',
        Reauthenticator::class                => 'reauthentication',
        FreshnessGate::class                  => 'reauthentication and freshness',
        FactorChangeGate::class               => 'factor changes',
        SessionRevoker::class                 => 'revocation on factor removal and reset',
        SessionTransition::class              => 'the return to pending',
        ProofStore::class                     => 'the proof store',
        FirstFactorResolver::class            => 'the first factor',
        VerifiedSignInRecorder::class         => 'the recorder of MFA\'s verified test sign-ins',
        ChallengeGateway::class               => 'code challenges',
        FactorCodeCounters::class             => 'code challenges and their counters',
        TenantRequirement::class              => 'MFA\'s tenant requirement',
        EventContextResolver::class           => 'the event context',
        ActiveTenantResolver::class           => 'the active tenant',
        SubjectTypeResolver::class            => 'the subject type',
        ActiveStateResolver::class            => 'the active state',
        ApplicationResolver::class            => 'and the application',
        PasskeyFactorGate::class              => 'the passkey factor gate',
        PasskeyGateway::class                 => 'MFA\'s passkey ceremonies',
        ReauthenticationSessions::class       => 'SSO\'s re-authentication sessions',
        SessionRevocation::class              => 'its session revocation',
        ExternalIdentityLinks::class          => '`laravel-authentication`\'s external identity links',
        Linker::class                         => 'its linker',
        LinkStorage::class                    => 'link storage',
        ExternalEvidencePolicy::class         => '`laravel-authentication`\'s external evidence policy',
        Freshness::class                      => 'SSO\'s freshness',
        ApplicationPolicy::class              => 'application policy',
        LinkEmailMatcher::class               => 'link email matcher',
        LinkConfirmation::class               => 'SSO\'s link confirmation',
        EvidencePolicy::class                 => 'SSO\'s per-connection evidence policy',
        TenantAuthenticationPolicy::class     => '`laravel-authentication`\'s tenant authentication policy',
        TenantMembership::class               => 'SSO\'s tenant membership',
        LinkEligibility::class                => 'its link eligibility',
        PrincipalScope::class                 => 'its principal scope',
        EnforcementInheritance::class         => 'SSO\'s enforcement inheritance',
    ];

    /** @var list<class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>> The capabilities `adapters.mfa` or `adapters.sso` governs. */
    private const array CAPABILITIES = [
        MfaSeams::class,
        PasskeySeams::class,
        ContextSeams::class,
        SsoSeams::class,
        TenancySeams::class,
    ];

    /**
     * Every seam a capability the switches govern binds is named in the
     * `adapters` section.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheAdaptersSectionNamesEverySeamTheSwitchesBind(): void
    {
        $app      = $this->app ?? self::fail('The application has not booted.');
        $config   = $app->make(Repository::class);
        $section  = self::section('Adapters');
        $unnamed  = [];
        $missing  = [];
        $bindings = array_merge(...array_map(static fn (string $capability): array => self::capability($app->make($capability))->seams($config), self::CAPABILITIES));

        foreach ($bindings as $binding) {

            $name = self::NAMES[$binding->abstract] ?? null;

            if ($name === null) {
                $unnamed[] = $binding->abstract;

                continue;
            }

            if (str_contains($section, $name)) {
                continue;
            }

            $missing[] = $name;
        }

        self::assertSame([], $unnamed, 'A seam the switches bind has no name in this test.');
        self::assertSame([], $missing, 'The adapters section does not name every seam the switches bind.');
    }

    /**
     * The `adapters` section says the tenant authentication policy is bound
     * while `sso` is on, whatever `mfa` says, and is the application's to bind,
     * a mandatory one while SSO's enforcement is on or a requirement is named,
     * once `sso` is off.
     *
     * @return void
     */
    public function testTheAdaptersSectionSaysWhenTheTenantPolicyIsTheApplicationsToBind(): void
    {
        $section = self::section('Adapters');

        self::assertStringContainsString('While `sso` is on, the package also binds `laravel-authentication`\'s tenant authentication policy', $section);
        self::assertStringContainsString('whatever `mfa` says', $section);
        self::assertStringContainsString('With `sso` off, bind it yourself: it is mandatory while `sso.features.enforcement` is on', $section);
        self::assertStringContainsString('or a tenant MFA requirement is named or bound', $section);
    }

    /**
     * The `tenancy` section says the requirement reaches MFA only while
     * `adapters.mfa` is on, and the tenant authentication policy only while
     * `adapters.sso` is.
     *
     * @return void
     */
    public function testTheTenancySectionSaysWhichSwitchesTheRequirementReachesThrough(): void
    {
        $section = self::section('Tenancy');

        self::assertStringContainsString('to MFA\'s tenant requirement while `adapters.mfa` is on', $section);
        self::assertStringContainsString('tenant authentication policy while `adapters.sso` is on', $section);
        self::assertStringContainsString('With `adapters.sso` off, bind that policy yourself', $section);
        self::assertStringContainsString('with both off nothing of the package\'s reads it', $section);
    }

    /**
     * The `tenancy` section tells the application to report a changed answer,
     * or a changed exemption, inside the transaction that publishes it and once
     * more after that commits, as `laravel-authentication`'s strict cut-off
     * asks, never with one call alone.
     *
     * @return void
     */
    public function testTheTenancySectionAsksForTheStrictCutOff(): void
    {
        $section = self::section('Tenancy');

        self::assertStringContainsString('call `Iam::tenantPolicies()->changed($tenant)` inside the transaction that publishes the change, on the storage connection', $section);
        self::assertStringContainsString('and once more after that transaction commits', $section);
        self::assertStringContainsString('call it twice the same way, once inside that transaction and once after it commits', $section);
        self::assertStringContainsString('Report the same whenever the answer of SSO\'s `EnforcementExemption` changes', $section);
    }

    /**
     * The comment of the packaged configuration's section under the heading,
     * its lines joined by single spaces.
     *
     * @param  string  $heading
     * @return string
     */
    private static function section(string $heading): string
    {
        $file = (string) file_get_contents(dirname(__DIR__, 3) . '/config/iam.php');

        self::assertSame(1, preg_match('/\|\s+' . preg_quote($heading, '/') . '\n.*?\*\//s', $file, $match), sprintf('The configuration has no [%s] section.', $heading));

        $lines = array_map(static fn (string $line): string => trim(ltrim(trim($line), '|')), explode("\n", $match[0]));

        return implode(' ', array_filter($lines, static fn (string $line): bool => $line !== '' && !str_starts_with($line, '---') && $line !== '*/'));
    }

    /**
     * The capability, as one that provides seams.
     *
     * @param  mixed  $capability
     * @return \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams
     */
    private static function capability(mixed $capability): ProvidesSeams
    {
        self::assertInstanceOf(ProvidesSeams::class, $capability);

        return $capability;
    }
}
