<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Iam\Mfa\FirstFactorResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaContextContributor;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * The stateless-guard reproduction of sinemacula/laravel-iam#3: a person signed
 * in with a bearer token verifies a further factor on one request, and the
 * verification counts on the next request with the same token, with no Laravel
 * session started or kept by either, and the request's authentication context
 * reports it under `mfa` (`mfa.accepted`).
 *
 * Every adapter between `laravel-authentication` and MFA is bound by this
 * package's binding rule, as an application gets them: MFA's proof store and
 * first-factor resolver are this package's, so the sign-in is the token's
 * session and its proofs are the ones `laravel-authentication` records, and the
 * verified proof reaches the session through the step-up adapter's
 * `Auth::sessions()->stepUp()`. The `mfa` namespace is this package's
 * contributor's, which reads the same session's proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreAdapter::class)]
#[CoversClass(FirstFactorResolverAdapter::class)]
#[CoversClass(StepUpAdapter::class)]
#[CoversClass(MfaContextContributor::class)]
final class StatelessVerificationTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /**
     * A verification made on one request counts on the next request with the
     * same bearer token, and on no other session of the person's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationCountsOnTheNextRequestWithTheSameToken(): void
    {
        $person = $this->createPerson();
        $token  = $this->signIn($person)->tokens->accessToken->reveal();
        $other  = $this->signIn($person)->tokens->accessToken->reveal();
        $factor = $this->confirmedFactor($person);

        $this->request('GET', '/protected', $token)->assertUnauthorized();
        $this->request('GET', '/context', $token)->assertOk()->assertExactJson(['mfa' => false]);

        $verified = $this->request('POST', '/verify', $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)]);

        $verified->assertOk()->assertExactJson(['verified' => true, 'session' => false]);

        $this->request('GET', '/protected', $token)->assertOk()->assertExactJson(['reached' => true, 'session' => false]);
        $this->request('GET', '/context', $token)->assertOk()->assertExactJson(['mfa' => true]);
        $this->request('GET', '/protected', $other)->assertUnauthorized();
        $this->request('GET', '/context', $other)->assertOk()->assertExactJson(['mfa' => false]);
    }

    /**
     * Define the routes the requests are made to, on the stateless guard and
     * with no session middleware.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('verify', static function (Request $request): JsonResponse {

            $result = Mfa::verify(CallerContext::fromRequest($request), Submission::factor($request->string('factor')->toString(), $request->string('code')->toString()));

            return new JsonResponse(['verified' => $result->isVerified(), 'session' => $request->hasSession()]);
        })->middleware('auth:' . self::GUARD);

        $router->get('protected', static fn (Request $request): JsonResponse => new JsonResponse(['reached' => true, 'session' => $request->hasSession()]))
            ->middleware(['auth:' . self::GUARD, 'mfa']);

        $router->get('context', static fn (): JsonResponse => new JsonResponse(['mfa' => Auth::context()?->get('mfa.accepted')]))
            ->middleware('auth:' . self::GUARD);
    }

    /**
     * Make a request as a new one, with the bearer token and nothing the
     * previous request bound.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  string  $token
     * @param  array<string, mixed>  $data
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Throwable
     */
    private function request(string $method, string $uri, string $token, array $data = []): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($token)->json($method, $uri, $data);
    }

    /**
     * A confirmed authenticator app factor of the person's on the guard's
     * application.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function confirmedFactor(Person $person): Factor
    {
        return Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => ProofOwner::of($person)->key,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => self::GUARD,
        ]);
    }
}
