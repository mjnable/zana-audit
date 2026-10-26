<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Configuration\ConfigurationInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Container\Contracts\ServiceResolverInterface;
use Zana\Core\ServiceProvider;
use Zana\Database\ConnectionInterface;
use Zana\Security\SecurityContext;

/**
 * Registers the revision store (DatabaseRevisionStore on the default
 * connection, table audit.table, unless the application registered one) and
 * Revisions (scoped), whose author is the signed-in user with mj-zana/security.
 */
final class AuditServiceProvider extends ServiceProvider
{
    public function register(ServiceCollectionInterface $services): void
    {
        $services
            ->trySingleton(RevisionStoreInterface::class, static function (ServiceResolverInterface $r): RevisionStoreInterface {
                $connection = $r->get(ConnectionInterface::class);
                assert($connection instanceof ConnectionInterface);

                return new DatabaseRevisionStore($connection, $r->get(ConfigurationInterface::class)->string('audit.table', 'audit_revisions'));
            })
            ->scoped(Revisions::class, static function (ServiceResolverInterface $r): Revisions {
                $store = $r->get(RevisionStoreInterface::class);
                assert($store instanceof RevisionStoreInterface);
                $security = class_exists(SecurityContext::class) && $r->has(SecurityContext::class) ? $r->get(SecurityContext::class) : null;

                return new Revisions($store, $security instanceof SecurityContext ? static fn (): ?string => $security->user()?->identifier() : null);
            });
    }

    public function origin(): string
    {
        return 'package:mj-zana/audit';
    }
}
