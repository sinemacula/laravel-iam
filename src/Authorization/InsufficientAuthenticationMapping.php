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
 * Renders `laravel-authorization`'s insufficient-authentication exception
 * (AUTHZ-9.6) as MFA's step-up exception (IAM-6.4, AUTHZ-14.1), so a request a
 * policy statement refuses for how its session was authenticated is answered as
 * MFA's route gate answers one, and only MFA produces step-up responses:
 * whatever the application renders for MFA's exception (its RFC 9470 challenge,
 * `toArray()` as the body) is what the client gets for both.
 *
 * Laravel turns an authorization exception into an HTTP exception before any
 * render callback is asked, so the callback this registers is asked about the
 * HTTP exception, and maps it only when the exception it was made from is
 * `laravel-authorization`'s. Laravel hands the callback the request alone, and
 * MFA's own reader turns it into MFA's caller (`CallerContext::fromRequest()`,
 * the default guard's identity on its application); the caller's session is the
 * one the bound subject resolver names for the request, the very key
 * `laravel-authorization` decided the caller's checks on, read there because
 * nothing hands it to a render callback. The core (`stepUp()`) takes that
 * caller, that session and the refusal as plain values, and reads nothing of
 * the request.
 *
 * Only a refusal decided on the caller's own session is mapped: its decision
 * read its requirements in that session (`Decision::$freshness`, compared by
 * fingerprint, as `laravel-authorization` compares one). A refusal about a
 * subject the caller names (`Authorization::for($account)->authorize()`) was
 * decided on no session, so every part was unmet without asking, and no step-up
 * by the caller could ever meet it: it stays Laravel's 403, rather than sending
 * the client into a step-up it cannot complete.
 *
 * The refusal names the requirements any one of which, met, would allow the
 * check; MFA's exception holds one. The first MFA can express is the one asked
 * for, whole, as MFA's (`RequirementTranslator`), with the factors MFA offers
 * the caller's session and whether its identity holds a confirmed factor, as
 * MFA's route gate builds its own; what meets it, and what the response says,
 * are MFA's. A refusal none of whose requirements MFA can express (one naming
 * an assurance level MFA does not know) is left as it is: Laravel's 403.
 *
 * It is registered while the authorization and MFA capabilities' switches are
 * both on, as the binding rule read them, so it and the requirement checker are
 * on together or not at all, on Laravel's own exception handler; an application
 * whose handler is not Laravel's maps the exception itself. A render callback
 * the application registered first for the same HTTP exception answers before
 * it. The core is resolved from the application current when the exception is
 * rendered, so under Octane it is the request's sandbox's. It holds nothing
 * between calls (IAM-8.1).
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
     * Register the mapping on Laravel's exception handler, once it is resolved,
     * while the authorization and MFA capabilities' switches were both on as
     * the binding rule read them, which the caller hands in (`$on`): read again
     * here, a switch a later provider wrote would map the step-up while
     * `laravel-authorization`'s refusing checker judges, or leave it unmapped
     * while MFA judges.
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
     * MFA's step-up exception for the caller the refusal was about: the first
     * of its requirements MFA can express, with the factors MFA offers the
     * caller and whether its identity holds a confirmed factor; `null` when MFA
     * can express none, or when the refusal was not decided on the caller's
     * session (`$session`, its key), so no step-up by the caller could meet it.
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
     * Whether the refusal was decided on the session: the decision it carries
     * read its requirements in that very session, compared as
     * `laravel-authorization` compares one, by its fingerprint. A refusal about
     * a subject with no session (one the caller names, `Authorization::for()`),
     * or another session, or carrying no decision, was not, and no step-up of
     * the caller's could meet it.
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
     * Register the render callback on the handler, when it is Laravel's.
     *
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     * @return void
     */
    private static function mapOn(ExceptionHandler $handler): void
    {
        if (!$handler instanceof Handler) {
            return;
        }

        $handler->renderable(static function (HttpException $exception, Request $request) use ($handler): ?Response {

            $refusal = $exception->getPrevious();

            if (!$refusal instanceof AuthorizationRefusal) {
                return null;
            }

            $container = Container::getInstance();
            $session   = $container->make(SubjectResolver::class)->resolve()?->session;
            $stepUp    = $container->make(self::class)->stepUp(CallerContext::fromRequest($request), $session, $refusal);

            return $stepUp === null ? null : $handler->render($request, $stepUp);
        });
    }
}
