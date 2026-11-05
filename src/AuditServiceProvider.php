<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Audit\Console\InstallLogCommand;
use Zana\Audit\Console\LogCommand;
use Zana\Audit\Console\PruneCommand;
use Zana\Audit\Console\VerifyCommand;
use Zana\Audit\Inspection\AuditLogCheck;
use Zana\Audit\Inspection\AuditLogSection;
use Zana\Configuration\ConfigurationInterface;
use Zana\Console\ConsoleKernel;
use Zana\Container\Contracts\ContainerInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Container\Contracts\ServiceResolverInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\InspectionSection;
use Zana\Core\ScopeKeys;
use Zana\Core\ServiceProvider;
use Zana\Database\ConnectionInterface;
use Zana\Events\ListenerProvider;
use Zana\Http\RequestContext;
use Zana\Security\Event\SecurityEvent;
use Zana\Security\SecurityContext;

/**
 * Registers content revisions: the revision store (DatabaseRevisionStore on
 * the default connection, table audit.table, unless the application
 * registered one) and Revisions (scoped), whose author is the signed-in user
 * with mj-zana/security.
 *
 * And the security audit log (2.15, ADR-030): AuditLogStore (table
 * audit.log.table, chained with audit.log.chain), AuditLog (scoped: the
 * signed-in user, the request's client address, the correlation id),
 * AuditedBehavior, the audit: commands, and its check and inspect section.
 * With audit.log.enabled (false by default), it records mj-zana/security's
 * events and checks the log's table and chain.
 */
final class AuditServiceProvider extends ServiceProvider
{
    private const string LOG_CONTEXT = 'Zana\\Logging\\LogContext';

    public function register(ServiceCollectionInterface $services): void
    {
        $services
            ->trySingleton(RevisionStoreInterface::class, static function (ServiceResolverInterface $r): RevisionStoreInterface {
                $connection = $r->get(ConnectionInterface::class);
                assert($connection instanceof ConnectionInterface);

                return new DatabaseRevisionStore($connection, self::config($r)->string('audit.table', 'audit_revisions'));
            })->uses(ConnectionInterface::class, ConfigurationInterface::class)
            ->scoped(Revisions::class, static function (ServiceResolverInterface $r): Revisions {
                $store = $r->get(RevisionStoreInterface::class);
                assert($store instanceof RevisionStoreInterface);

                return new Revisions($store, self::user($r));
            })->uses(RevisionStoreInterface::class, SecurityContext::class)
            ->singleton(AuditLogStore::class, static function (ServiceResolverInterface $r): AuditLogStore {
                $connection = $r->get(ConnectionInterface::class);
                assert($connection instanceof ConnectionInterface);
                $config = self::config($r);

                return new AuditLogStore($connection, $config->string('audit.log.table', AuditLogStore::TABLE), $config->bool('audit.log.chain', false));
            })->uses(ConnectionInterface::class, ConfigurationInterface::class)
            ->scoped(AuditLog::class, static function (ServiceResolverInterface $r): AuditLog {
                $request = class_exists(RequestContext::class) && $r->has(RequestContext::class) ? $r->get(RequestContext::class) : null;
                $correlation = $r->metadata()->attribute(ScopeKeys::CORRELATION_ID);

                return new AuditLog(
                    self::store($r),
                    self::user($r),
                    $request instanceof RequestContext ? static fn (): ?string => $request->has() ? $request->clientIp() : null : null,
                    is_string($correlation) ? static fn (): string => $correlation : null,
                );
            })->uses(AuditLogStore::class, SecurityContext::class, RequestContext::class)
            ->scoped(AuditedBehavior::class, static function (ServiceResolverInterface $r): AuditedBehavior {
                $log = $r->get(AuditLog::class);
                assert($log instanceof AuditLog);

                return new AuditedBehavior($log);
            })->uses(AuditLog::class)
            // A listener is resolved from the root container: the security events carry the user and address.
            ->singleton(SecurityEventsRecorder::class, static function (ServiceResolverInterface $r): SecurityEventsRecorder {
                $context = $r->has(self::LOG_CONTEXT) ? $r->get(self::LOG_CONTEXT) : null;
                $correlation = is_object($context) && method_exists($context, 'all')
                    ? static function () use ($context): ?string {
                        $values = $context->all();
                        $id = is_array($values) ? ($values[ScopeKeys::CORRELATION_ID] ?? null) : null;

                        return is_string($id) ? $id : null;
                    }
                    : null;

                return new SecurityEventsRecorder(self::store($r), $correlation);
            })->uses(AuditLogStore::class)
            // The store is resolved lazily: resolving the tagged checks and sections must not need the database.
            ->singleton(AuditLogCheck::class, static fn (ServiceResolverInterface $r): AuditLogCheck => new AuditLogCheck(
                static fn (): AuditLogStore => self::store($r),
                self::config($r)->bool('audit.log.enabled', false),
            ))->uses(AuditLogStore::class, ConfigurationInterface::class)
            ->tag(ApplicationCheck::TAG, AuditLogCheck::class)
            ->singleton(AuditLogSection::class, static fn (ServiceResolverInterface $r): AuditLogSection => new AuditLogSection(
                static fn (): AuditLogStore => self::store($r),
                self::config($r)->bool('audit.log.enabled', false),
            ))->uses(AuditLogStore::class, ConfigurationInterface::class)
            ->tag(InspectionSection::TAG, AuditLogSection::class);

        if (class_exists(ConsoleKernel::class)) {
            foreach ([InstallLogCommand::class, VerifyCommand::class, PruneCommand::class, LogCommand::class] as $command) {
                $services->singleton($command)->tag(ConsoleKernel::TAG, $command);
            }
        }
    }

    public function boot(ContainerInterface $container): void
    {
        $config = $container->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);
        if (!$config->bool('audit.log.enabled', false)) {
            return;
        }
        if (interface_exists(SecurityEvent::class) && class_exists(ListenerProvider::class) && $container->has(ListenerProvider::class)) {
            $listeners = $container->get(ListenerProvider::class);
            assert($listeners instanceof ListenerProvider);
            $listeners->listen(SecurityEvent::class, SecurityEventsRecorder::class);
        }
    }

    public function origin(): string
    {
        return 'package:mj-zana/audit';
    }

    /**
     * @return (\Closure(): ?string)|null
     */
    private static function user(ServiceResolverInterface $r): ?\Closure
    {
        $security = class_exists(SecurityContext::class) && $r->has(SecurityContext::class) ? $r->get(SecurityContext::class) : null;

        return $security instanceof SecurityContext ? static fn (): ?string => $security->user()?->identifier() : null;
    }

    private static function store(ServiceResolverInterface $r): AuditLogStore
    {
        $store = $r->get(AuditLogStore::class);
        assert($store instanceof AuditLogStore);

        return $store;
    }

    private static function config(ServiceResolverInterface $r): ConfigurationInterface
    {
        $config = $r->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);

        return $config;
    }
}
