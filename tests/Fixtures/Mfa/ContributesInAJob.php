<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa;

use Illuminate\Bus\Queueable;
use Illuminate\Container\Container;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Models\Person;

/**
 * A queued job that builds the `mfa` namespace outside any request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContributesInAJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /** @var ?array<string, mixed> The keys the last job contributed, or `null` before any has run. */
    public static ?array $contributed = null;

    /**
     * Constructor.
     *
     * @param  int|string  $person
     * @param  string  $session
     * @param  string  $guard
     */
    public function __construct(

        /** The person's key. */
        public int|string $person,

        /** The session's key. */
        public string $session,

        /** The guard (the application) the context is built for. */
        public string $guard,
    ) {}

    /**
     * Contribute the `mfa` keys of the session, and keep them for the test.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function handle(): void
    {
        $person  = Person::query()->findOrFail($this->person);
        $session = Session::query()->findOrFail($this->session);

        self::$contributed = self::contributor()->contribute(self::subject($person, $session, $this->guard));
    }

    /**
     * The contributor registered under `mfa`.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor
     *
     * @throws \LogicException
     */
    public static function contributor(): AuthenticationContextContributor
    {
        $container   = Container::getInstance();
        $contributor = $container->make($container->make(ContextContributors::class)->registered()['mfa'] ?? throw new \LogicException('Nothing is registered under `mfa`.'));

        if (!$contributor instanceof AuthenticationContextContributor) {
            throw new \LogicException('The `mfa` contributor is no contributor.');
        }

        return $contributor;
    }

    /**
     * The contribution subject for the session, made of plain values.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Context\ContributionSubject
     */
    public static function subject(Person $person, EloquentSession&Model $session, string $guard): ContributionSubject
    {
        $id  = ProofOwner::of($person)->key;
        $key = $session->getKey();

        $context = new AuthenticationContext(
            subjectType: SubjectType::PERSON,
            identityType: $person->getMorphClass(),
            identityId: $id,
            principalType: $person->getMorphClass(),
            principalId: $id,
            tenantType: null,
            tenantId: null,
            application: $guard,
            sessionId: is_scalar($key) ? (string) $key : null,
            amr: [],
            authTime: null,
            mfa: false,
            recoveryCode: false,
            multifactor: false,
            secondsSinceStepUp: null,
            credential: null,
            scopes: null,
            ip: null,
        );

        return new ContributionSubject($context, $person, $person, null, $session);
    }
}
