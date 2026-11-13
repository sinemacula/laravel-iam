<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Mfa\Assurance\Channel as MfaChannel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;

/**
 * Translates a proof's channel between `laravel-authentication` and MFA, and to
 * and from MFA's array form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChannelTranslator
{
    /**
     * MFA's channel for `laravel-authentication`'s.
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
     * The channel's array form, which holds the full destination.
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
     * The channel read back strictly from its array form.
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
