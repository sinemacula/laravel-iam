<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;

/**
 * The factor a further proof made by `Concerns\InteractsWithIam` is made with:
 * a confirmed factor of the type the identity already holds, so acting as the
 * same person again, or as a person seeded with a factor, enrols nothing more,
 * or, when it holds none, a confirmed fixture factor of the type enrolled for
 * it now through the application, in MFA's configured factor model.
 *
 * Either way the proof names a factor the identity holds in MFA's factor table,
 * so this package's proof store counts it.
 *
 * Stateless: the identity's factors are read on every call.
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
     * The id, as a proof made with it names it, of a confirmed factor of the
     * type the identity holds, enrolling one through the application when it
     * holds none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $type
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \Throwable
     */
    public function held(MultiFactorAuthenticatable $identity, string $application, string $type): string
    {
        foreach ($identity->authFactors()->useWritePdo()->get()->all() as $factor) {
            if ($factor->isConfirmed() && $factor->getType() === $type) {
                return ProofStoreAdapter::factorReference($factor);
            }
        }

        return ProofStoreAdapter::factorReference($this->enrol($identity, $application, $type));
    }

    /**
     * Enrol a confirmed fixture factor of the type for the identity, through
     * the application, in MFA's configured factor model.
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
