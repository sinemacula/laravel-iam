<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Proofs\Channel as AuthChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection as AuthenticationKeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthPurpose;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties as AuthenticationProperties;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Iam\Mfa\Translation\ChannelTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Sso\ConnectionTrust;
use SineMacula\Laravel\Mfa\Assurance\Channel as MfaChannel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties as MfaProperties;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\KeyProtection as MfaKeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind as MfaProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Unit tests for translating proofs between `laravel-authentication` and MFA.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofTranslator::class)]
#[CoversClass(ProviderTrust::class)]
final class ProofTranslatorTest extends TestCase
{
    /** @var string The application the sign-in is on. */
    private const string APPLICATION = 'api';

    /** @var string The sign-in's reference. */
    private const string SESSION = '42';

    /** @var int The identity's verification generation. */
    private const int GENERATION = 3;

    /** @var string When the proofs were made. */
    private const string PROVED_AT = '2026-11-05 09:30:15';

    /**
     * Rows of `[laravel-authentication's kind, MFA's kind]` for every kind.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, 1: \SineMacula\Laravel\Mfa\Enums\ProofKind}>
     */
    public static function provideProofKinds(): iterable
    {
        yield 'first factor' => [AuthKind::FIRST_FACTOR, MfaProofKind::FIRST_FACTOR];

        yield 'first factor reauthentication' => [AuthKind::FIRST_FACTOR_REAUTHENTICATION, MfaProofKind::FIRST_FACTOR_REAUTHENTICATION];

        yield 'external reauthentication' => [AuthKind::EXTERNAL_REAUTHENTICATION, MfaProofKind::FIRST_FACTOR_REAUTHENTICATION];

        yield 'additional factor' => [AuthKind::ADDITIONAL_FACTOR, MfaProofKind::ADDITIONAL_FACTOR];

        yield 'recovery code' => [AuthKind::RECOVERY_CODE, MfaProofKind::RECOVERY_CODE];
    }

    /**
     * Every proof kind crosses as MFA's of the same kind.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $authentication
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $mfa
     * @return void
     */
    #[DataProvider('provideProofKinds')]
    public function testEveryKindIsMfasOfTheSameKind(AuthKind $authentication, MfaProofKind $mfa): void
    {
        self::assertSame($mfa, self::translator()->kind($authentication));
    }

    /**
     * Rows of `[laravel-authentication's purpose, MFA's purpose]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose, 1: \SineMacula\Laravel\Mfa\Enums\Purpose}>
     */
    public static function providePurposes(): iterable
    {
        yield 'sign in' => [AuthPurpose::SIGN_IN, MfaPurpose::SIGN_IN];

        yield 'reauthenticate' => [AuthPurpose::REAUTHENTICATE, MfaPurpose::REAUTHENTICATE];

        yield 'step up' => [AuthPurpose::STEP_UP, MfaPurpose::STEP_UP];

        yield 'enrollment' => [AuthPurpose::ENROLLMENT, MfaPurpose::ENROLLMENT];
    }

    /**
     * Every purpose crosses as itself, both ways.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $authentication
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $mfa
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testEveryPurposeCrossesAsItself(AuthPurpose $authentication, MfaPurpose $mfa): void
    {
        self::assertSame($mfa, self::translator()->purpose($authentication));
        self::assertSame($authentication, self::translator()->toAuthenticationPurpose($mfa));
    }

    /**
     * Rows of `[laravel-authentication's properties, MFA's]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\ObservedProperties, 1: \SineMacula\Laravel\Mfa\Assurance\ObservedProperties}>
     */
    public static function provideObservedProperties(): iterable
    {
        yield 'nothing observed' => [new AuthenticationProperties, MfaProperties::none()];

        yield 'user presence' => [new AuthenticationProperties(userPresence: true), new MfaProperties(userPresence: true)];

        yield 'user verification' => [new AuthenticationProperties(userVerification: false), new MfaProperties(userVerification: false)];

        yield 'backup eligibility' => [new AuthenticationProperties(backupEligible: true), new MfaProperties(backupEligibility: true)];

        yield 'backup state' => [new AuthenticationProperties(backupState: false), new MfaProperties(backupState: false)];

        yield 'phishing resistance' => [new AuthenticationProperties(phishingResistant: true), new MfaProperties(phishingResistance: true)];

        yield 'hardware key' => [new AuthenticationProperties(keyProtection: AuthenticationKeyProtection::HARDWARE), new MfaProperties(keyProtection: MfaKeyProtection::HARDWARE)];

        yield 'software key' => [new AuthenticationProperties(keyProtection: AuthenticationKeyProtection::SOFTWARE), new MfaProperties(keyProtection: MfaKeyProtection::SOFTWARE)];
    }

    /**
     * Every observed property crosses under its own name, both ways.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $authentication
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $mfa
     * @return void
     */
    #[DataProvider('provideObservedProperties')]
    public function testEveryObservedPropertyCrossesUnderItsOwnName(AuthenticationProperties $authentication, MfaProperties $mfa): void
    {
        self::assertEquals($mfa, self::translator()->properties($authentication));
        self::assertEquals($authentication, self::translator()->toAuthenticationProperties($mfa));
    }

    /**
     * Properties MFA would refuse are refused.
     *
     * @return void
     */
    public function testPropertiesMfaWouldRefuseAreRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        self::translator()->properties(new AuthenticationProperties(backupEligible: false, backupState: true));
    }

    /**
     * A first factor is bound to the sign-in and stamped with its generation.
     *
     * @return void
     */
    public function testAFirstFactorIsBoundToTheSignIn(): void
    {
        $observed = new AuthenticationProperties(userPresence: true);
        $proof    = self::recorded(AuthKind::FIRST_FACTOR, AuthPurpose::SIGN_IN, new AuthChannel(AuthChannelKind::PASSWORD, 'ignored'), observed: $observed);

        $translated = self::translator()->toMfa($proof, self::signIn(), ProviderTrust::withheld());

        self::assertSame(MfaProofKind::FIRST_FACTOR, $translated->kind);
        self::assertSame('password', $translated->method);
        self::assertChannel(MfaChannelKind::PASSWORD, null, $translated->channel);
        self::assertNull($translated->reference);
        self::assertEquals(new MfaProperties(userPresence: true), $translated->properties);
        self::assertTrue($translated->provedAt->equalTo(CarbonImmutable::parse(self::PROVED_AT)));
        self::assertEquals(new ProofBinding(GenericUser::class, '7', self::APPLICATION, self::SESSION, MfaPurpose::SIGN_IN), $translated->binding);
        self::assertSame(self::GENERATION, $translated->generation);
        self::assertNull($translated->challengeId);
    }

    /**
     * An additional factor keeps its factor and its channel's reference.
     *
     * @return void
     */
    public function testAnAdditionalFactorKeepsItsFactorAndChannel(): void
    {
        $proof = self::recorded(AuthKind::ADDITIONAL_FACTOR, AuthPurpose::STEP_UP, new AuthChannel(AuthChannelKind::AUTHENTICATOR_APP, 'factor-1'), 'totp', 'factor-1');

        $translated = self::translator()->toMfa($proof, self::signIn(), ProviderTrust::withheld());

        self::assertSame(MfaProofKind::ADDITIONAL_FACTOR, $translated->kind);
        self::assertSame('totp', $translated->method);
        self::assertSame('factor-1', $translated->reference);
        self::assertChannel(MfaChannelKind::AUTHENTICATOR_APP, 'factor-1', $translated->channel);
        self::assertSame(MfaPurpose::STEP_UP, $translated->binding->purpose);
    }

    /**
     * A recovery code travels on no channel in MFA.
     *
     * @return void
     */
    public function testARecoveryCodeTravelsOnNoChannel(): void
    {
        $proof = self::recorded(AuthKind::RECOVERY_CODE, AuthPurpose::SIGN_IN, new AuthChannel(AuthChannelKind::UNKNOWN), 'recovery_code', 'set-1');

        $translated = self::translator()->toMfa($proof, self::signIn(), ProviderTrust::withheld());

        self::assertSame(MfaProofKind::RECOVERY_CODE, $translated->kind);
        self::assertNull($translated->channel);
        self::assertSame('set-1', $translated->reference);
    }

    /**
     * An external reauthentication is on the provider's channel.
     *
     * @return void
     */
    public function testAnExternalReauthenticationIsAFirstFactorReauthenticationOnTheProvidersChannel(): void
    {
        $channel = new AuthChannel(AuthChannelKind::EXTERNAL_PROVIDER, 'connection-1');
        $proof   = self::recorded(AuthKind::EXTERNAL_REAUTHENTICATION, AuthPurpose::REAUTHENTICATE, $channel, 'external_provider', evidence: self::evidence());

        $translated = self::translator()->toMfa($proof, self::signIn(), ProviderTrust::accepted(null));

        self::assertSame(MfaProofKind::FIRST_FACTOR_REAUTHENTICATION, $translated->kind);
        self::assertChannel(MfaChannelKind::EXTERNAL_PROVIDER, 'connection-1', $translated->channel);
        self::assertSame(MfaPurpose::REAUTHENTICATE, $translated->binding->purpose);
    }

    /**
     * Rows of `[reauthentication, accepted evidence, trust counts evidence, expected connection]`.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: bool, 3: ?string}>
     */
    public static function provideExternalProofs(): iterable
    {
        foreach (['a first factor' => false, 'a reauthentication' => true] as $name => $reauthentication) {

            yield $name . ' with accepted evidence, counted' => [$reauthentication, true, true, 'connection-1'];

            yield $name . ' with no accepted evidence, counted' => [$reauthentication, false, true, null];

            yield $name . ' with accepted evidence, withheld' => [$reauthentication, true, false, null];

            yield $name . ' with no accepted evidence, withheld' => [$reauthentication, false, false, null];
        }
    }

    /**
     * A provider's proof names its connection only with accepted evidence.
     *
     * @param  bool  $reauthentication
     * @param  bool  $accepted
     * @param  bool  $counted
     * @param  ?string  $connection
     * @return void
     */
    #[DataProvider('provideExternalProofs')]
    public function testAProvidersProofNamesItsConnectionOnlyWithAcceptedEvidence(bool $reauthentication, bool $accepted, bool $counted, ?string $connection): void
    {
        $kind    = $reauthentication ? AuthKind::EXTERNAL_REAUTHENTICATION : AuthKind::FIRST_FACTOR;
        $purpose = $reauthentication ? AuthPurpose::REAUTHENTICATE : AuthPurpose::SIGN_IN;
        $channel = new AuthChannel(AuthChannelKind::EXTERNAL_PROVIDER, 'connection-1');
        $proof   = self::recorded($kind, $purpose, $channel, 'external_provider', evidence: $accepted ? self::evidence() : null);
        $trust   = $counted ? ProviderTrust::accepted(null) : ProviderTrust::withheld();

        self::assertChannel(MfaChannelKind::EXTERNAL_PROVIDER, $connection, self::translator()->toMfa($proof, self::signIn(), $trust)->channel);
    }

    /**
     * A provider's proof recorded on no connection names none.
     *
     * @return void
     */
    public function testAProvidersProofOnNoConnectionNamesNone(): void
    {
        $proof = self::recorded(AuthKind::FIRST_FACTOR, AuthPurpose::SIGN_IN, new AuthChannel(AuthChannelKind::EXTERNAL_PROVIDER), 'external_provider', evidence: self::evidence());

        self::assertChannel(MfaChannelKind::EXTERNAL_PROVIDER, null, self::translator()->toMfa($proof, self::signIn(), ProviderTrust::accepted(null))->channel);
    }

    /**
     * An external reauthentication on another channel is on the provider's.
     *
     * @return void
     */
    public function testAnExternalReauthenticationOnAnotherChannelIsOnTheProvidersChannel(): void
    {
        $proof = self::recorded(AuthKind::EXTERNAL_REAUTHENTICATION, AuthPurpose::REAUTHENTICATE, new AuthChannel(AuthChannelKind::EMAIL, 'ada@example.test'), 'external_provider');

        self::assertChannel(MfaChannelKind::EXTERNAL_PROVIDER, null, self::translator()->toMfa($proof, self::signIn(), ProviderTrust::withheld())->channel);
    }

    /**
     * A proof MFA would refuse to build is refused.
     *
     * @return void
     */
    public function testAProofMfaWouldRefuseIsRefused(): void
    {
        $proof = self::recorded(AuthKind::FIRST_FACTOR, AuthPurpose::STEP_UP, new AuthChannel(AuthChannelKind::PASSWORD));

        $this->expectException(\InvalidArgumentException::class);

        self::translator()->toMfa($proof, self::signIn(), ProviderTrust::withheld());
    }

    /**
     * A verified proof is the proof result `laravel-authentication` takes.
     *
     * @return void
     */
    public function testAVerifiedProofIsTheProofResultLaravelAuthenticationTakes(): void
    {
        $identity = self::identity();
        $channel  = new MfaChannel(MfaChannelKind::SMS, '+447700900123');
        $proof    = self::proof(MfaProofKind::ADDITIONAL_FACTOR, $channel, 'factor-2', MfaPurpose::STEP_UP, new MfaProperties(userVerification: true));
        $result   = VerificationResult::verified($proof, self::evaluation(true, true), ['otp', 'mfa', 'sms'], 'sms', true);

        $translated = self::translator()->toResult($result, $identity);

        self::assertSame(AuthKind::ADDITIONAL_FACTOR, $translated->kind);
        self::assertSame('sms', $translated->method);
        self::assertSame(AuthChannelKind::SMS, $translated->channel->kind);
        self::assertSame('+447700900123', $translated->channel->reference);
        self::assertSame('factor-2', $translated->factor);
        self::assertEquals(new AuthenticationProperties(userVerification: true), $translated->observed);
        self::assertTrue($translated->evaluation->accepted);
        self::assertTrue($translated->evaluation->multifactor);
        self::assertTrue($translated->evaluation->additionalVerification);
        self::assertSame(['otp', 'sms'], $translated->methods);
        self::assertTrue($translated->authenticatedAt->equalTo(CarbonImmutable::parse(self::PROVED_AT)));
        self::assertSame($identity, $translated->binding->identity);
        self::assertSame(self::APPLICATION, $translated->binding->application);
        self::assertSame(self::SESSION, $translated->binding->sessionId);
        self::assertSame(AuthPurpose::STEP_UP, $translated->binding->purpose);
    }

    /**
     * Rows of `[refreshes multifactor, multifactor of the whole session]`.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideMultifactorEvidence(): iterable
    {
        yield 'refreshes it, the whole session multifactor' => [true, true];
        yield 'refreshes it, the whole session not multifactor' => [true, false];
        yield 'does not refresh it, the whole session multifactor' => [false, true];
        yield 'does not refresh it, the whole session not multifactor' => [false, false];
    }

    /**
     * The proof is multifactor only when it refreshes the evidence.
     *
     * @param  bool  $refreshes
     * @param  bool  $wholeSession
     * @return void
     */
    #[DataProvider('provideMultifactorEvidence')]
    public function testTheProofIsMultifactorOnlyWhenItRefreshesTheEvidence(bool $refreshes, bool $wholeSession): void
    {
        $proof  = self::proof(MfaProofKind::ADDITIONAL_FACTOR, new MfaChannel(MfaChannelKind::EMAIL, 'ada@example.test'), 'factor-3', MfaPurpose::SIGN_IN);
        $result = VerificationResult::verified($proof, self::evaluation(true, $wholeSession), ['otp'], 'email', $refreshes);

        $translated = self::translator()->toResult($result, self::identity());

        self::assertTrue($translated->evaluation->accepted);
        self::assertSame($refreshes, $translated->evaluation->multifactor);
        self::assertTrue($translated->evaluation->additionalVerification);
        self::assertTrue($translated->authenticatedAt->equalTo($proof->provedAt));
        self::assertSame(['otp'], $translated->methods);
        self::assertSame(AuthPurpose::SIGN_IN, $translated->binding->purpose);
    }

    /**
     * A recovery code travels on an unknown channel.
     *
     * @return void
     */
    public function testARecoveryCodeTravelsOnAnUnknownChannel(): void
    {
        $proof  = self::proof(MfaProofKind::RECOVERY_CODE, null, 'set-1', MfaPurpose::SIGN_IN);
        $result = VerificationResult::verified($proof, self::evaluation(true, false), [], 'recovery_code');

        $translated = self::translator()->toResult($result, self::identity());

        self::assertSame(AuthKind::RECOVERY_CODE, $translated->kind);
        self::assertSame(AuthChannelKind::UNKNOWN, $translated->channel->kind);
        self::assertNull($translated->channel->reference);
    }

    /**
     * A failed verification made no proof to hand over, and is refused.
     *
     * @return void
     */
    public function testAFailedVerificationIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Only a verification that made a proof can be handed to laravel-authentication.');

        self::translator()->toResult(VerificationResult::failed(FailureReason::INVALID_CODE, 'wrong code'), self::identity());
    }

    /**
     * Assert MFA's channel is of the given kind and names the given reference.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  ?string  $reference
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @return void
     */
    private static function assertChannel(MfaChannelKind $kind, ?string $reference, ?MfaChannel $channel): void
    {
        self::assertNotNull($channel);
        self::assertSame($kind, $channel->kind);
        self::assertSame($reference, $channel->reference());
    }

    /**
     * Build the translator.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator
     */
    private static function translator(): ProofTranslator
    {
        return new ProofTranslator(new ChannelTranslator, new ConnectionTrust(new Container));
    }

    /**
     * Build the sign-in the recorded proofs are read for.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\Translation\SignIn
     */
    private static function signIn(): SignIn
    {
        return new SignIn(ProofOwner::of(new GenericUser(['id' => 7])), self::APPLICATION, self::SESSION, self::GENERATION);
    }

    /**
     * Build an identity `laravel-authentication` signs in.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function identity(): Identity
    {
        return new class (['id' => 7]) extends GenericUser implements Identity {};
    }

    /**
     * Build a proof a session recorded.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  string  $method
     * @param  ?string  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private static function recorded(
        AuthKind $kind,
        AuthPurpose $purpose,
        AuthChannel $channel,
        string $method = 'password',
        ?string $factor = null,
        ?AuthenticationProperties $observed = null,
        ?ExternalEvidence $evidence = null,
    ): RecordedProof {
        $observed ??= new AuthenticationProperties;

        return new RecordedProof('proof-1', $kind, $purpose, $method, $channel, $factor, $observed, null, [], CarbonImmutable::parse(self::PROVED_AT), $evidence);
    }

    /**
     * Build the evidence an external provider asserted, as SSO accepted it.
     *
     * @return \SineMacula\Laravel\Authentication\External\ExternalEvidence
     */
    private static function evidence(): ExternalEvidence
    {
        return new ExternalEvidence(['pwd', 'mfa'], null, CarbonImmutable::parse(self::PROVED_AT));
    }

    /**
     * Build a proof MFA verified on the sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $kind
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  string  $reference
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function proof(MfaProofKind $kind, ?MfaChannel $channel, string $reference, MfaPurpose $purpose, ?MfaProperties $properties = null): Proof
    {
        $binding = new ProofBinding(GenericUser::class, '7', self::APPLICATION, self::SESSION, $purpose);

        $method = $channel?->kind->value ?? 'recovery_code';

        return new Proof($kind, $method, $channel, $reference, $properties ?? MfaProperties::none(), CarbonImmutable::parse(self::PROVED_AT), $binding, self::GENERATION);
    }

    /**
     * Build MFA's evaluation of the sign-in's proofs.
     *
     * @param  bool  $accepted
     * @param  bool  $multifactor
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    private static function evaluation(bool $accepted, bool $multifactor): Evaluation
    {
        return new Evaluation($accepted, $multifactor, $multifactor ? AssuranceLevel::AAL2 : AssuranceLevel::AAL1, false, false, [], [], []);
    }
}
