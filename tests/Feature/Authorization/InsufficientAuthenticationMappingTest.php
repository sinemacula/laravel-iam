<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Config\Repository as RepositoryContract;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException as AuthorizationRefusal;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\InsufficientAuthenticationMapping;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException as StepUp;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\TurnsMfaOffWhileRegistering;
use Tests\TestCase;

/**
 * Feature tests for rendering insufficient authentication as MFA's step-up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InsufficientAuthenticationMapping::class)]
#[CoversClass(IamServiceProvider::class)]
final class InsufficientAuthenticationMappingTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var string The key of the caller's session, which the refusals are decided on. */
    private const string SESSION = 'the-callers-session';

    /**
     * Resolve the caller as signed in with the refusals' session.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->resolveTheCallerOnTheSession();
    }

    /**
     * The first candidate MFA can express is asked for, with its factors.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testTheFirstRequirementMfaCanExpressIsAskedFor(): void
    {
        $refusal = self::refusal(['assurance_level' => ['min' => 'gold']], ['multifactor' => ['max_age' => 300], 'additional_verification' => []]);
        $stepUp  = $this->mapping()->stepUp(CallerContext::nobody(self::GUARD), self::SESSION, $refusal);

        self::assertInstanceOf(StepUp::class, $stepUp);
        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION, RequirementPart::MULTIFACTOR], $stepUp->requirement->parts());
        self::assertSame(300, $stepUp->requirement->maxAge(RequirementPart::MULTIFACTOR));
        self::assertSame([], $stepUp->offered);
        self::assertNull($stepUp->operation);
        self::assertFalse($stepUp->hasConfirmedFactor);
    }

    /**
     * A refusal none of whose requirements MFA can express asks for no step-up.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testARefusalMfaCannotExpressAsksForNoStepUp(): void
    {
        self::assertNull($this->mapping()->stepUp(CallerContext::nobody(self::GUARD), self::SESSION, self::refusal(['assurance_level' => ['min' => 'gold']])));
    }

    /**
     * Only a refusal decided on the caller's own session asks for a step-up.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testOnlyARefusalDecidedOnTheCallersSessionAsksForAStepUp(): void
    {
        $caller  = CallerContext::nobody(self::GUARD);
        $mapping = $this->mapping();

        self::assertNull($mapping->stepUp($caller, self::SESSION, self::refusalIn(null, ['multifactor' => []])));
        self::assertNull($mapping->stepUp($caller, self::SESSION, self::refusalIn('another-session', ['multifactor' => []])));
        $undecided = new AuthorizationRefusal([new UnmetRequirement(AuthenticationRequirement::fromOperand(['multifactor' => []]), ['multifactor'])]);

        $unread = new AuthorizationRefusal($undecided->requirements(), null, Decision::insufficientAuthentication(DecisionStage::ALLOW, [], $undecided->requirements()));

        self::assertNull($mapping->stepUp($caller, self::SESSION, $undecided));
        self::assertNull($mapping->stepUp($caller, self::SESSION, $unread));
        self::assertNull($mapping->stepUp($caller, null, self::refusalIn(null, ['multifactor' => []])));
        self::assertInstanceOf(StepUp::class, $mapping->stepUp($caller, self::SESSION, self::refusal(['multifactor' => []])));
    }

    /**
     * A refusal about a named subject stays Laravel's 403.
     *
     * @return void
     */
    public function testARefusalAboutANamedSubjectStaysLaravels403(): void
    {
        $this->postJson('/delegate')->assertForbidden();
    }

    /**
     * A refusal with no subject stays Laravel's 403.
     *
     * @return void
     */
    public function testARefusalWithNoSubjectStaysLaravels403(): void
    {
        $resolver = self::createStub(SubjectResolver::class);

        $resolver->method('resolve')->willReturn(null);

        $this->app?->instance(SubjectResolver::class, $resolver);

        $this->postJson('/refund')->assertForbidden();
    }

    /**
     * A refusal from a route renders as MFA's 401 step-up.
     *
     * @return void
     */
    public function testARefusalIsRenderedAsMfasStepUp(): void
    {
        $this->postJson('/refund')->assertUnauthorized()->assertExactJson(['message' => (new StepUp(Requirement::none()))->getMessage()]);
    }

    /**
     * What MFA cannot express renders as Laravel renders it.
     *
     * @return void
     */
    public function testWhatIsNotMappedIsRenderedAsLaravelRendersIt(): void
    {
        $this->postJson('/void')->assertForbidden();
        $this->postJson('/teapot')->assertStatus(418);
    }

    /**
     * With the authorization capability's switch off, nothing is mapped.
     *
     * @return void
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testNothingIsMappedWithTheAuthorizationSwitchOff(): void
    {
        $this->postJson('/refund')->assertForbidden();
    }

    /**
     * With the MFA capability's switch off, nothing is mapped.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testNothingIsMappedWithTheMfaSwitchOff(): void
    {
        $this->postJson('/refund')->assertForbidden();
    }

    /**
     * The mapping registers on Laravel's handler whenever it is resolved.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testTheMappingIsRegisteredOnLaravelsHandlerWheneverItIsResolved(): void
    {
        $refusal = new HttpException(403, 'denied', self::refusal(['multifactor' => []]));
        $request = Request::create('/refund', 'POST', server: ['HTTP_ACCEPT' => 'application/json']);

        $later = $this->bareApplication();

        $later->singleton(ExceptionHandler::class, static fn (Application $app): Handler => new Handler($app));

        InsufficientAuthenticationMapping::register($later, true);

        self::assertSame(401, $later->make(ExceptionHandler::class)->render($request, $refusal)->getStatusCode());

        $resolved = $this->bareApplication();

        $resolved->instance(ExceptionHandler::class, new Handler($resolved));

        InsufficientAuthenticationMapping::register($resolved, true);

        self::assertSame(401, $resolved->make(ExceptionHandler::class)->render($request, $refusal)->getStatusCode());

        $other   = $this->bareApplication();
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('render')->never();

        $other->instance(ExceptionHandler::class, $handler);

        InsufficientAuthenticationMapping::register($other, true);

        $off = $this->bareApplication();

        $off->instance(ExceptionHandler::class, new Handler($off));

        InsufficientAuthenticationMapping::register($off, false);

        self::assertSame(403, $off->make(ExceptionHandler::class)->render($request, $refusal)->getStatusCode());
    }

    /**
     * Turning MFA off later binds neither the checker nor the mapping.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheMappingFollowsTheSwitchesAsTheSeamsWereBound(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsMfaOffWhileRegistering::class]);

        $app = $this->app ?? self::fail('The application has not booted.');

        $this->resolveTheCallerOnTheSession();

        self::assertFalse(MfaSeams::isOn($app->make('config')));
        self::assertInstanceOf(RefusingRequirementChecker::class, self::resolve($app, AuthenticationRequirementChecker::class));

        $this->postJson('/refund')->assertForbidden();
    }

    /**
     * Define the routes that throw.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('refund', static fn (): JsonResponse => self::failWith(self::refusal(['multifactor' => []])));
        $router->post('void', static fn (): JsonResponse => self::failWith(self::refusal(['assurance_level' => ['min' => 'gold']])));
        $router->post('delegate', static fn (): JsonResponse => self::failWith(self::refusalIn(null, ['multifactor' => []])));
        $router->post('teapot', static fn (): JsonResponse => self::failWith(new HttpException(418)));
    }

    /**
     * Resolve the caller as signed in with the refusals' session.
     *
     * @return void
     */
    private function resolveTheCallerOnTheSession(): void
    {
        $resolver = self::createStub(SubjectResolver::class);

        $resolver->method('resolve')->willReturn(new Subject(new \stdClass, null, null, self::GUARD, self::GUARD, self::SESSION));

        $this->app?->instance(SubjectResolver::class, $resolver);
    }

    /**
     * Fail the request with the exception, as a refusing route does.
     *
     * @param  \Throwable  $exception
     * @return never
     *
     * @throws \Throwable
     */
    private static function failWith(\Throwable $exception): never
    {
        throw $exception;
    }

    /**
     * A bare application sharing this test's mapping, every switch on.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function bareApplication(): Application
    {
        $app = new Application(dirname(__DIR__, 3));

        $app->instance('config', new Repository);
        $app->alias('config', RepositoryContract::class);
        $app->instance(InsufficientAuthenticationMapping::class, $this->mapping());

        Application::setInstance($this->app);

        return $app;
    }

    /**
     * Resolve whatever the container holds for the abstract.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function resolve(Application $app, string $abstract): mixed
    {
        return $app->make($abstract);
    }

    /**
     * The mapping's core.
     *
     * @return \SineMacula\Laravel\Iam\Authorization\InsufficientAuthenticationMapping
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function mapping(): InsufficientAuthenticationMapping
    {
        $mapping = $this->app?->make(InsufficientAuthenticationMapping::class);

        self::assertInstanceOf(InsufficientAuthenticationMapping::class, $mapping);

        return $mapping;
    }

    /**
     * A refusal with a candidate per operand, on the caller's session.
     *
     * @param  array<string, array<string, int|string>>  ...$operands
     * @return \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     *
     * @throws \InvalidArgumentException
     */
    private static function refusal(array ...$operands): AuthorizationRefusal
    {
        return self::refusalIn(self::SESSION, ...$operands);
    }

    /**
     * A refusal with a candidate per operand, decided in the given session.
     *
     * @param  ?string  $session
     * @param  array<string, array<string, int|string>>  ...$operands
     * @return \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     *
     * @throws \InvalidArgumentException
     */
    private static function refusalIn(?string $session, array ...$operands): AuthorizationRefusal
    {
        $requirements = array_map(
            static fn (AuthenticationRequirement $requirement): UnmetRequirement => new UnmetRequirement($requirement, $requirement->names()),
            array_map(AuthenticationRequirement::fromOperand(...), array_values($operands)),
        );

        $decision = Decision::insufficientAuthentication(DecisionStage::ALLOW, [], $requirements)->withFreshness(new RequirementFreshness($session));

        return new AuthorizationRefusal($requirements, null, $decision);
    }
}
