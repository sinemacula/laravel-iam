<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Mfa\Assurance\Channel as MfaChannel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;

/**
 * Translates a proof's channel between `laravel-authentication` and MFA, and to
 * and from the array form a channel is stored and carried in (IAM-3.11,
 * IAM-3.14).
 *
 * Both members spell seven channel kinds the same. `laravel-authentication`'s
 * eighth, `recovery` (the application's own account recovery, a first factor
 * only), has no kind in MFA, so it is MFA's `unknown`, one way only: MFA never
 * hands one back. They differ on the reference too: `laravel-authentication`
 * keeps one on any kind, while MFA refuses one on a password or an unknown
 * channel, which name nothing, so it is dropped there; on every other kind it
 * crosses unchanged, since two proofs on the same channel and destination are
 * not independent. The array form is MFA's own (`kind` and `reference`), read
 * back as strictly as MFA reads it, and holds the full destination, so it is
 * for storing a proof, never for an event, a log or a response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChannelTranslator
{
    /**
     * MFA's channel for `laravel-authentication`'s, without the reference on a
     * kind that takes none; a `recovery` channel is MFA's `unknown`.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @return \SineMacula\Laravel\Mfa\Assurance\Channel
     *
     * @throws \InvalidArgumentException
     */
    public function toMfa(AuthenticationChannel $channel): MfaChannel
    {
        $kind = $channel->kind === AuthenticationChannelKind::RECOVERY ? MfaChannelKind::UNKNOWN : MfaChannelKind::from($channel->kind->value);

        return new MfaChannel($kind, $kind->takesReference() ? $channel->reference : null);
    }

    /**
     * `laravel-authentication`'s channel for MFA's, with its reference.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @return \SineMacula\Laravel\Authentication\Proofs\Channel
     *
     * @throws \InvalidArgumentException
     */
    public function toAuthentication(MfaChannel $channel): AuthenticationChannel
    {
        return new AuthenticationChannel(AuthenticationChannelKind::from($channel->kind->value), $channel->reference());
    }

    /**
     * The array form of `laravel-authentication`'s channel: MFA's, with the
     * channel's kind and the reference MFA keeps.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @return array{kind: string, reference: ?string}
     *
     * @throws \InvalidArgumentException
     */
    public function toArray(AuthenticationChannel $channel): array
    {
        return $this->toMfa($channel)->toArray();
    }

    /**
     * `laravel-authentication`'s channel read back from its array form; an
     * unknown kind or field, or a reference the kind takes none of, is refused.
     *
     * @param  array<array-key, mixed>  $data
     * @return \SineMacula\Laravel\Authentication\Proofs\Channel
     *
     * @throws \InvalidArgumentException
     */
    public function fromArray(array $data): AuthenticationChannel
    {
        return $this->toAuthentication(MfaChannel::fromArray($data));
    }
}
