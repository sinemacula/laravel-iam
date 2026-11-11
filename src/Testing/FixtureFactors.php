<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;

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
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration MFA's factor model is declared in. */
        private Repository $config,
    ) {}

    /**
     * The id of the identity's confirmed factor of the level's type, enrolling
     * one on the application when it holds none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
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
                return ProofStoreAdapter::factorReference($factor);
            }
        }

        return ProofStoreAdapter::factorReference($this->enrol($identity, $application, $type));
    }

    /**
     * Enrol a confirmed factor of the type for the identity on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \Throwable
     */
    private function enrol(MultiFactorAuthenticatable $identity, string $application, string $type): Factor
    {
        $model  = ConfiguredModels::factor($this->config);
        $factor = new $model;
        $owner  = $factor->authenticatable();
        $holder = IdentityReference::of($identity);

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
