<?php

declare(strict_types=1);

namespace Zana\Audit;

/**
 * One entry of the security audit log (FE-58, 2.15): who did what, to what,
 * when, from where, in which request. Entries are never changed.
 */
final readonly class AuditEntry
{
    /**
     * @param string $occurredAt UTC, ISO 8601 with microseconds
     * @param array<string, mixed> $details
     * @param int|null $sequence The position in the hash chain, when the log is chained
     */
    public function __construct(
        public string $occurredAt,
        public string $action,
        public ?string $actor = null,
        public ?string $subject = null,
        public ?string $clientIp = null,
        public ?string $correlationId = null,
        public array $details = [],
        public ?int $id = null,
        public ?int $sequence = null,
        public ?string $previousHash = null,
        public ?string $hash = null,
    ) {
    }
}
