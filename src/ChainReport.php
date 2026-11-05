<?php

declare(strict_types=1);

namespace Zana\Audit;

/**
 * What AuditLogStore::verify() found: whether the hash chain is intact, how
 * many entries it checked, and where it breaks.
 */
final readonly class ChainReport
{
    public function __construct(
        public bool $intact,
        public int $checked,
        public ?int $brokenAt = null,
        public ?string $problem = null,
    ) {
    }
}
