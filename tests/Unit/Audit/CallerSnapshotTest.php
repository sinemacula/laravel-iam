<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit;

use Illuminate\Events\Dispatcher;
use Illuminate\Log\Context\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Audit\CallerSnapshot;
use Tests\Fixtures\Models\Person;

/**
 * Unit tests for the caller as plain values (IAM-9.7): taken from
 * `laravel-authentication`'s event context, or none when it names no guard or
 * no identity; carried in hidden Context as scalars under one key and read back
 * exactly; a missing, partial or malformed envelope read as no caller, never an
 * exception; and forgotten leaving everything else in Context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerSnapshot::class)]
final class CallerSnapshotTest extends TestCase
{
    /**
     * The caller is the event context's guard, identity, principal, tenant
     * identifier and session identifier.
     *
     * @return void
     */
    public function testTheCallerIsTheEventContexts(): void
    {
        $person = new Person;

        $person->forceFill(['id' => 7]);

        $caller = CallerSnapshot::of(new EventContext('api', new ClientContext(null, null), $person, $person, sessionId: 'session-1'));

        self::assertEquals(new CallerSnapshot('api', Person::class, '7', Person::class, '7', null, 'session-1'), $caller);
    }

    /**
     * An event context naming no guard, or no identity, is no caller.
     *
     * @return void
     */
    public function testAContextNamingNoGuardOrIdentityIsNoCaller(): void
    {
        $person = new Person;

        $person->forceFill(['id' => 7]);

        self::assertNull(CallerSnapshot::of(new EventContext(null, new ClientContext(null, null), $person)));
        self::assertNull(CallerSnapshot::of(new EventContext('api', new ClientContext(null, null))));
    }

    /**
     * Carried in Context, the caller is read back exactly, under its one hidden
     * key, as scalars.
     *
     * @return void
     */
    public function testACarriedCallerIsReadBackExactly(): void
    {
        $context = self::context();
        $caller  = new CallerSnapshot('api', 'person', '7', 'team', '9', 'tenant-1', 'session-1');

        $caller->carryInto($context);

        self::assertEquals($caller, CallerSnapshot::carriedIn($context));
        self::assertSame([
            'guard'          => 'api',
            'identity_type'  => 'person',
            'identity_id'    => '7',
            'principal_type' => 'team',
            'principal_id'   => '9',
            'tenant_id'      => 'tenant-1',
            'session_id'     => 'session-1',
        ], $context->getHidden(CallerSnapshot::KEY));
        self::assertSame([], $context->all());
    }

    /**
     * Context carrying no caller carries none.
     *
     * @return void
     */
    public function testAContextCarryingNoCallerCarriesNone(): void
    {
        self::assertNull(CallerSnapshot::carriedIn(self::context()));
    }

    /**
     * Provide envelopes that carry no caller.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        $whole = ['guard' => 'api', 'identity_type' => 'person', 'identity_id' => '7'];

        yield 'no map' => ['api'];
        yield 'an object that is no map' => [new \ArrayObject($whole)];
        yield 'no guard' => [array_diff_key($whole, ['guard' => true])];
        yield 'no identity type' => [array_diff_key($whole, ['identity_type' => true])];
        yield 'no identity id' => [array_diff_key($whole, ['identity_id' => true])];
        yield 'an identity id that is no string' => [[...$whole, 'identity_id' => 7]];
        yield 'a session that is no string' => [[...$whole, 'session_id' => ['session-1']]];
    }

    /**
     * A malformed envelope is no caller, never an exception.
     *
     * @param  mixed  $envelope
     * @return void
     */
    #[DataProvider('provideMalformedEnvelopes')]
    public function testAMalformedEnvelopeIsNoCaller(mixed $envelope): void
    {
        $context = self::context();

        $context->addHidden(CallerSnapshot::KEY, $envelope);

        self::assertNull(CallerSnapshot::carriedIn($context));
    }

    /**
     * Only the parts it names are optional: a principal, a tenant and a session
     * left out are none.
     *
     * @return void
     */
    public function testTheOptionalPartsMayBeLeftOut(): void
    {
        $context = self::context();

        $context->addHidden(CallerSnapshot::KEY, ['guard' => 'api', 'identity_type' => 'person', 'identity_id' => '7']);

        self::assertEquals(new CallerSnapshot('api', 'person', '7'), CallerSnapshot::carriedIn($context));
    }

    /**
     * Forgetting the caller leaves everything else in Context.
     *
     * @return void
     */
    public function testForgettingTheCallerLeavesTheRest(): void
    {
        $context = self::context();

        $context->addHidden('audit-log.request_id', 'request-1');
        $context->add('visible', 'kept');

        (new CallerSnapshot('api', 'person', '7'))->carryInto($context);

        CallerSnapshot::forgetIn($context);

        self::assertNull($context->getHidden(CallerSnapshot::KEY));
        self::assertSame('request-1', $context->getHidden('audit-log.request_id'));
        self::assertSame(['visible' => 'kept'], $context->all());
    }

    /**
     * An empty Context repository.
     *
     * @return \Illuminate\Log\Context\Repository
     */
    private static function context(): Repository
    {
        return new Repository(new Dispatcher);
    }
}
