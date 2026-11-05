<?php

declare(strict_types=1);

namespace Zana\Audit\Tests;

use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Zana\Audit\AuditedBehavior;
use Zana\Audit\AuditLogStore;
use Zana\Audit\AuditServiceProvider;
use Zana\Audit\Inspection\AuditLogCheck;
use Zana\Audit\Inspection\AuditLogSection;
use Zana\Console\ConsoleKernel;
use Zana\Console\ConsoleServiceProvider;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Container\ScopeMetadata;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\InspectionSection;
use Zana\Core\ScopeKeys;
use Zana\Database\ConnectionInterface;
use Zana\Database\DatabaseServiceProvider;
use Zana\Events\EventsServiceProvider;
use Zana\Mediator\HandlerMap;
use Zana\Mediator\MediatorInterface;
use Zana\Mediator\MediatorServiceProvider;
use Zana\Security\Event\SignInSucceeded;
use Zana\Testing\ConsoleTester;

final class RefundOrderHandler
{
    public function __invoke(RefundOrder $command): string
    {
        return "refunded {$command->orderId}";
    }
}

/**
 * The audit log in an application: audit:install-log and migrate, security
 * events recorded through the dispatcher, #[Audited] commands through the
 * mediator with the scope's correlation id, check, inspect, audit:log,
 * audit:verify and audit:prune; and an application that keeps revisions only.
 */
final class AuditLogApplicationTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        $this->base = str_replace('\\', '/', sys_get_temp_dir()) . '/zana-audit-app-' . bin2hex(random_bytes(4));
        mkdir("{$this->base}/var", 0777, true);
    }

    protected function tearDown(): void
    {
        exec(PHP_OS_FAMILY === 'Windows' ? 'rmdir /s /q ' . escapeshellarg(str_replace('/', '\\', $this->base)) : 'rm -rf ' . escapeshellarg($this->base));
    }

    public function testTheLogRecordsSecurityEventsAndAuditedCommands(): void
    {
        $app = $this->app([
            'audit.log.enabled' => true,
            'audit.log.chain' => true,
            'audit.log.retention_days' => 365,
            'mediator.behaviors' => [AuditedBehavior::class],
        ]);
        $console = new ConsoleTester($app->container()->get(ConsoleKernel::class));
        $check = self::tagged($app, ApplicationCheck::TAG, AuditLogCheck::class);

        $this->assertSame(['audit.log'], self::ids($check->findings($app)), 'no table yet');
        $this->assertStringContainsString('_create_audit_log_tables.php', $console->run('audit:install-log')->output());
        $this->assertSame(0, $console->run('migrate')->exitCode());
        $this->assertSame([], self::ids($check->findings($app)));

        $events = $app->container()->get(EventDispatcherInterface::class);
        assert($events instanceof EventDispatcherInterface);
        $events->dispatch(new SignInSucceeded('7', '198.51.100.7'));

        $app->container()->get(HandlerMap::class)->map(RefundOrder::class, RefundOrderHandler::class);
        $scope = $app->container()->createScope(ScopeMetadata::http()->withAttribute(ScopeKeys::CORRELATION_ID, 'req-42'));
        $mediator = $scope->get(MediatorInterface::class);
        assert($mediator instanceof MediatorInterface);
        $this->assertSame('refunded o-9', $mediator->send(new RefundOrder('o-9', 2500, Currency::Usd, '4111111111111111')));
        $scope->dispose();

        $store = $app->container()->get(AuditLogStore::class);
        assert($store instanceof AuditLogStore);
        $entries = $store->entries();
        $this->assertSame([['order.refund', 'o-9', 'req-42'], ['security.sign_in', 'user:7', null]], array_map(static fn ($e): array => [$e->action, $e->subject, $e->correlationId], $entries));

        $log = $console->run('audit:log --action=order.refund')->output();
        $this->assertStringContainsString('order.refund', $log);
        $this->assertStringNotContainsString('security.sign_in', $log);
        $this->assertStringContainsString('chain is intact: 2 entries checked', $console->run('audit:verify')->output());
        $this->assertStringContainsString('Deleted 0 audit log entries older than 365 days.', $console->run('audit:prune')->output());
        $this->assertSame(2, self::tagged($app, InspectionSection::TAG, AuditLogSection::class)->inspect($app)['entries'] ?? null);

        $db = $app->container()->get(ConnectionInterface::class);
        assert($db instanceof ConnectionInterface);
        $db->table(AuditLogStore::TABLE)->where('sequence', 1)->update(['client_ip' => '203.0.113.66']);
        $this->assertSame(['audit.chain'], self::ids($check->findings($app)), 'an edited entry');
        $this->assertSame(1, $console->run('audit:verify')->exitCode());
    }

    public function testAnApplicationWithRevisionsOnlyIsUnchanged(): void
    {
        $app = $this->app([]);
        $events = $app->container()->get(EventDispatcherInterface::class);
        assert($events instanceof EventDispatcherInterface);

        $events->dispatch(new SignInSucceeded('7'));   // no audit log table, and no listener: nothing fails

        $this->assertSame([], self::tagged($app, ApplicationCheck::TAG, AuditLogCheck::class)->findings($app));
        $this->assertSame(['enabled' => false], self::tagged($app, InspectionSection::TAG, AuditLogSection::class)->inspect($app));
        $this->assertStringContainsString('kept forever', (new ConsoleTester($app->container()->get(ConsoleKernel::class)))->run('audit:prune')->output());
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(array $config): ApplicationInterface
    {
        return Application::configure($this->base)->withEnvironment('testing')
            ->withProviders(DatabaseServiceProvider::class, EventsServiceProvider::class, MediatorServiceProvider::class, ConsoleServiceProvider::class, AuditServiceProvider::class)
            ->withConfiguration(['database.connections.main' => ['driver' => 'sqlite', 'database' => ':memory:'], ...$config])
            ->withServices(static fn (ServiceCollectionInterface $s) => $s->singleton(RefundOrderHandler::class))
            ->build();
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private static function ids(array $findings): array
    {
        return array_map(static fn (Finding $f): string => $f->id, $findings);
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    private static function tagged(ApplicationInterface $app, string $tag, string $class): object
    {
        foreach ($app->container()->tagged($tag) as $service) {
            if ($service instanceof $class) {
                return $service;
            }
        }
        self::fail("{$class} is not tagged {$tag}.");
    }
}
