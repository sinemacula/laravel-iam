<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Foundation\Application as Testbench;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Fixtures\Models\Person;

/**
 * Requirement check benchmark fixtures: an application with every member's
 * provider and this package's, on in-memory SQLite with MFA's and the people
 * fixture's tables, the requirement check adapter, and two subjects it judges.
 *
 * The check is the hottest path of the adapters between the two members:
 * `laravel-authentication` asks it on every sign-in, every pending action and
 * every judgement of a session. Each subject is a person's sign-in with its
 * first factor and further proofs held in memory, as `laravel-authentication`
 * hands them over once read: one further proof, and as many as one read
 * returns. A judgement translates the requirement and every proof into MFA's,
 * reads the identity's verification generation, the one statement it makes, and
 * has MFA's check judge them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequirementCheckBenchHarness
{
    /** @var string The guard, and the MFA application, the sign-ins are on. */
    private const string GUARD = 'api';

    /** @var int How long ago, at most, a proof that meets the requirement was made, in seconds. */
    private const int MAX_AGE = 3600;

    /** @var \SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter The check. */
    private RequirementCheckAdapter $check;

    /** @var \SineMacula\Laravel\Authentication\Requirements\Requirement An additional, multifactor verification within the hour. */
    private Requirement $requirement;

    /** @var \SineMacula\Laravel\Authentication\Requirements\RequirementSubject A sign-in with one further proof. */
    private RequirementSubject $oneProof;

    /** @var \SineMacula\Laravel\Authentication\Requirements\RequirementSubject A sign-in with as many further proofs as one read returns. */
    private RequirementSubject $longSession;

    /**
     * Build the application and the subjects, and check that each subject meets
     * the requirement through the adapter.
     *
     * @throws \LogicException
     */
    public function __construct()
    {
        $check = self::application()->make(RequirementCheckAdapter::class);

        $person = Person::query()->create(['name' => 'Ada', 'email' => 'ada@example.test', 'password' => 'correct horse battery staple']);
        $now    = CarbonImmutable::now()->startOfSecond();

        $this->check       = $check;
        $this->requirement = new Requirement(new RequirementPart(self::MAX_AGE), new RequirementPart(self::MAX_AGE));
        $this->oneProof    = self::subject($person, $now, 1);
        $this->longSession = self::subject($person, $now, RequirementSubject::MAX_LIMIT);

        foreach (['one further proof' => $this->isMetByOneProof(), 'a long session' => $this->isMetByALongSession()] as $subject => $met) {
            if (!$met) {
                throw new \LogicException(sprintf('The requirement check over %s did not find the requirement met.', $subject));
            }
        }
    }

    /**
     * Whether the sign-in with one further proof meets the requirement, as the
     * check judges it.
     *
     * @return bool
     */
    public function isMetByOneProof(): bool
    {
        return $this->check->evaluate($this->oneProof, $this->requirement)->isMet();
    }

    /**
     * Whether the sign-in with as many further proofs as one read returns meets
     * the requirement, as the check judges it.
     *
     * @return bool
     */
    public function isMetByALongSession(): bool
    {
        return $this->check->evaluate($this->longSession, $this->requirement)->isMet();
    }

    /**
     * The application, with every member's provider and this package's, its
     * guard and MFA application declared, and MFA's and the people fixture's
     * tables migrated.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private static function application(): Application
    {
        $root      = dirname(__DIR__, 2);
        $providers = [
            AuthenticationServiceProvider::class,
            AuthorizationServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
            AuditLogServiceProvider::class,
            IamServiceProvider::class,
        ];

        $app = Testbench::create(options: ['extra' => ['providers' => $providers, 'dont-discover' => ['*']]]);

        $app->make('config')->set([
            'app.key'                         => 'base64:' . base64_encode(str_repeat('b', 32)),
            'database.default'                => 'bench',
            'database.connections.bench'      => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''],
            'auth.defaults.guard'             => self::GUARD,
            'auth.guards.' . self::GUARD      => ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => ['password']]],
            'auth.providers.people'           => ['driver' => 'model', 'model' => Person::class],
            'hashing.bcrypt.rounds'           => 4,
            'mfa.applications.' . self::GUARD => [
                'types'        => ['totp'],
                'requirement'  => 'enrolled',
                'first_factor' => ['method' => 'password', 'channel' => 'password'],
            ],
        ]);

        $migrator = $app->make('migrator');

        $migrator->getRepository()->createRepository();
        $migrator->run([$root . '/vendor/sinemacula/laravel-mfa/database/migrations', $root . '/tests/Fixtures/database/migrations']);

        return $app;
    }

    /**
     * A sign-in of the person's with its password first factor and as many
     * further proofs, each an authenticator app code reported multifactor, made
     * a second apart, newest first, as `laravel-authentication` reads them.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $further
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementSubject
     */
    private static function subject(Person $person, CarbonImmutable $now, int $further): RequirementSubject
    {
        $password = new Channel(ChannelKind::PASSWORD);
        $app      = new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor');
        $observed = new ObservedProperties;
        $accepted = new Evaluation(true, true);
        $first    = new RecordedProof('first', ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'password', $password, null, $observed, null, ['pwd'], $now->subSeconds($further + 1));
        $proofs   = [];

        for ($proof = 0; $proof < $further; $proof++) {
            $madeAt   = $now->subSeconds($proof);
            $proofs[] = new RecordedProof('further-' . $proof, ProofKind::ADDITIONAL_FACTOR, Purpose::STEP_UP, 'totp', $app, 'factor', $observed, $accepted, ['otp'], $madeAt);
        }

        return new RequirementSubject($person, self::GUARD, null, $first, $now, static fn (): array => $proofs);
    }
}
