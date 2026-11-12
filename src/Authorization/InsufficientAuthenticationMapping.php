<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException as AuthorizationRefusal;
use SineMacula\Laravel\Iam\Authorization\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException as StepUp;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Renders `laravel-authorization`'s insufficient-authentication refusal as
 * MFA's step-up exception, when it was decided on the caller's session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InsufficientAuthenticationMapping
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** Translates the refusal's requirement into MFA's. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * Register the mapping when both switches were on at binding time.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  bool  $on
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function register(Application $app, bool $on): void
    {
        if (!$on) {
            return;
        }

        if ($app->resolved(ExceptionHandler::class)) {
            self::mapOn($app->make(ExceptionHandler::class));
        } else {
            $app->afterResolving(ExceptionHandler::class, static function (ExceptionHandler $handler): void {

                self::mapOn($handler);
            });
        }
    }

    /**
     * MFA's step-up for the first requirement MFA can express, or `null`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  ?string  $session
     * @param  \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException  $refusal
     * @return ?\SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     */
    public function stepUp(CallerContext $caller, ?string $session, AuthorizationRefusal $refusal): ?StepUp
    {
        if (!self::isDecidedOn($session, $refusal)) {
            return null;
        }

        foreach ($refusal->requirements() as $candidate) {

            try {
                $requirement = $this->requirements->toMfa($candidate->requirement);
            } catch (\InvalidArgumentException) {
                continue;
            }

            $confirmed = array_filter(Mfa::factors($caller), static fn (FactorSummary $factor): bool => $factor->status === FactorStatus::CONFIRMED);

            return new StepUp($requirement, Mfa::offeredFactors($caller), null, $confirmed !== []);
        }

        return null;
    }

    /**
     * Whether the refusal was decided on the session, compared by fingerprint.
     *
     * @param  ?string  $session
     * @param  \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException  $refusal
     * @return bool
     */
    private static function isDecidedOn(?string $session, AuthorizationRefusal $refusal): bool
    {
        $decided = $refusal->getDecision()?->freshness?->session;

        return $session !== null && $decided === (new RequirementFreshness($session))->session;
    }

    /**
     * Register the render callback on Laravel's own handler.
     *
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     * @return void
     */
    private static function mapOn(ExceptionHandler $handler): void
    {
        if (!$handler instanceof Handler) {
            return;
        }

        // Laravel wraps an authorization exception in an HTTP one first.
        $handler->renderable(static function (HttpException $exception, Request $request) use ($handler): ?Response {

            $refusal = $exception->getPrevious();

            if (!$refusal instanceof AuthorizationRefusal) {
                return null;
            }

            // A render callback gets no session, so read the bound resolver's.
            $container = Container::getInstance();
            $session   = $container->make(SubjectResolver::class)->resolve()?->session;
            $stepUp    = $container->make(self::class)->stepUp(CallerContext::fromRequest($request), $session, $refusal);

            return $stepUp === null ? null : $handler->render($request, $stepUp);
        });
    }
}
