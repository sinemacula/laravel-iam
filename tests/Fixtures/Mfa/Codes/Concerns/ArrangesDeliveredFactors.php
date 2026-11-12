<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Codes\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Models\Person;

/**
 * Stores the delivered factors code challenges are sent for (IAM-3.9): an SMS
 * or email factor of a person's on the application people sign in on, confirmed
 * as an enrolment confirmed in MFA leaves it, or pending with no enrolment
 * under way.
 *
 * An SMS factor's codes go to `DELIVERED_PHONE` unless the test names another
 * number, and an email factor's to the person's own address. A test that sends
 * through either also offers its type (`mfaTypes()`), and binds a sender or
 * names a gateway for it before the application boots. It is used with
 * `SignsInPeople` and `MigratesMembers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ArrangesDeliveredFactors
{
    /** @var string The number an SMS factor's codes go to, in E.164 form, unless the test names another. */
    protected const string DELIVERED_PHONE = '+447700900123';

    /**
     * Store a confirmed delivered factor of the person's: `sms` or `email`,
     * sent to the destination given or the type's own.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $type
     * @param  ?string  $destination
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function deliveredFactor(Person $person, string $type = 'sms', ?string $destination = null): Factor
    {
        return $this->storeDeliveredFactor($person, $type, $destination, FactorStatus::CONFIRMED);
    }

    /**
     * Store a pending delivered factor of the person's, with no enrolment under
     * way: `sms` or `email`, sent to the destination given or the type's own.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $type
     * @param  ?string  $destination
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function pendingDeliveredFactor(Person $person, string $type = 'sms', ?string $destination = null): Factor
    {
        return $this->storeDeliveredFactor($person, $type, $destination, FactorStatus::PENDING);
    }

    /**
     * The destination a delivered factor of the type sends to by default:
     * `DELIVERED_PHONE` for SMS, the person's own address for email.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $type
     * @return string
     */
    protected static function deliveredDestination(Person $person, string $type): string
    {
        return $type === 'email' ? $person->email : self::DELIVERED_PHONE;
    }

    /**
     * Store a delivered factor of the person's with the status given.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $type
     * @param  ?string  $destination
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorStatus  $status
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function storeDeliveredFactor(Person $person, string $type, ?string $destination, FactorStatus $status): Factor
    {
        return Factor::query()->create([
            'type'                 => $type,
            'destination'          => $destination ?? self::deliveredDestination($person, $type),
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => ProofOwner::of($person)->key,
            'label'                => $type === 'email' ? 'Email' : 'Phone',
            'status'               => $status->value,
            'application'          => self::GUARD,
            'confirmed_at'         => $status === FactorStatus::CONFIRMED ? CarbonImmutable::now() : null,
        ]);
    }
}
