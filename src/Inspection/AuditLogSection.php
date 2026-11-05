<?php

declare(strict_types=1);

namespace Zana\Audit\Inspection;

use Zana\Audit\AuditLogStore;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\InspectionSection;

/**
 * `inspect audit-log`: the number of entries, the oldest and newest, and
 * whether the log is chained.
 */
final readonly class AuditLogSection implements InspectionSection
{
    /**
     * @param \Closure(): AuditLogStore $store
     */
    public function __construct(private \Closure $store, private bool $enabled = true)
    {
    }

    public function name(): string
    {
        return 'audit-log';
    }

    public function inspect(ApplicationInterface $application): array
    {
        if (!$this->enabled) {
            return ['enabled' => false];
        }
        try {
            return ($this->store)()->counts();
        } catch (\Throwable $e) {
            return ['error' => 'The security audit log cannot be read: ' . strtok($e->getMessage(), "\n")];
        }
    }
}
