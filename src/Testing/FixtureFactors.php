<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The real factor a test helper's further proof names, as this package's proof
 * store counts no other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixtureFactors
{
    /**
     * The id of the identity's factor of the level's type, enrolled if none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    public function held(MultiFactorAuthenticatable $identity, string $application, AssuranceLevel $level): string
    {
        $type = match ($level) {
            AssuranceLevel::AAL1 => 'email',
            AssuranceLevel::AAL3 => 'passkey',
            default              => 'totp',
        };

        foreach ($identity->authFactors()->useWritePdo()->get()->all() as $factor) {
            if ($factor->isConfirmed() && $factor->getType() === $type) {
                return CodeTranslator::reference($factor);
            }
        }

        return CodeTranslator::reference(self::enrol($identity, $application, $type));
    }

    /**
     * Enrol a confirmed factor of the type for the identity on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    private static function enrol(MultiFactorAuthenticatable $identity, string $application, string $type): Factor
    {
        $factor = $identity->authFactors()->getModel()->newInstance();
        $owner  = $factor->authenticatable();
        $holder = ProofOwner::of($identity);

        $factor->forceFill([
            $owner->getMorphType()        => $holder->type,
            $owner->getForeignKeyName()   => $holder->key,
            $factor->getTypeName()        => $type,
            $factor->getApplicationName() => $application,
        ]);

        $factor->confirm();
        $factor->persist();

        return $factor;
    }
}
