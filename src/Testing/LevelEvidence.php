<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * The evidence a further proof of a level is made of, for
 * `Concerns\InteractsWithIam`: the type of the factor it is made with, which is
 * also its method, the kind of channel it travels on (to the synthetic address
 * for an email code, and to the factor itself otherwise), what was observed,
 * and the `amr` values MFA reports for a proof of that kind on its own (its
 * method's, then user presence and key protection when observed).
 *
 * The evidence is MFA's own helper's: an email code to a synthetic address for
 * AAL1, an authenticator app for AAL2, and a hardware-protected,
 * phishing-resistant passkey observing presence and user verification for AAL3,
 * which MFA's default combination policy rates AAL2, so it needs a policy that
 * rates such evidence AAL3.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LevelEvidence
{
    /** @var string The synthetic address an AAL1 proof's code travels to. */
    public const string EMAIL_ADDRESS = 'verified@example.test';

    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  list<string>  $amr
     */
    private function __construct(

        /** The type of the factor the proof is made with, which is also its method. */
        public string $type,

        /** The kind of channel the proof travels on. */
        public ChannelKind $kind,

        /** What was observed of the proof. */
        public ObservedProperties $properties,

        /** The `amr` values MFA reports for a proof of this kind on its own. */
        public array $amr,
    ) {}

    /**
     * The evidence of a further proof of the level.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return self
     */
    public static function of(AssuranceLevel $level): self
    {
        return match ($level) {
            AssuranceLevel::AAL1 => new self('email', ChannelKind::EMAIL, ObservedProperties::none(), ['otp']),
            AssuranceLevel::AAL3 => new self('passkey', ChannelKind::PASSKEY, self::hardwarePasskey(), ['pop', 'user', 'hwk']),
            default              => new self('totp', ChannelKind::AUTHENTICATOR_APP, ObservedProperties::none(), ['otp']),
        };
    }

    /**
     * A further proof of this evidence, made now with the factor, bound as
     * given, of the identity's verification generation.
     *
     * @param  string  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  int  $generation
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function proof(string $factor, ProofBinding $binding, int $generation): Proof
    {
        return new Proof(
            kind: ProofKind::ADDITIONAL_FACTOR,
            method: $this->type,
            channel: new Channel($this->kind, $this->kind === ChannelKind::EMAIL ? self::EMAIL_ADDRESS : $factor),
            reference: $factor,
            properties: $this->properties,
            provedAt: CarbonImmutable::now(),
            binding: $binding,
            generation: $generation,
        );
    }

    /**
     * What a passkey that observed presence, user verification and phishing
     * resistance, with a hardware-protected key, was observed to be.
     *
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     */
    private static function hardwarePasskey(): ObservedProperties
    {
        return new ObservedProperties(userPresence: true, userVerification: true, phishingResistance: true, keyProtection: KeyProtection::HARDWARE);
    }
}
