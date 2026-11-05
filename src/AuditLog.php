<?php

declare(strict_types=1);

namespace Zana\Audit;

use Closure;

/**
 * The security audit log (FE-58, ADR-030): an append-only record of
 * sensitive actions, for disputes and the data-protection rules.
 *
 *     $audit->record('order.refund', subject: "order:{$order->id}", details: ['amount' => 2500]);
 *
 * Registered scoped: the actor is the signed-in user (mj-zana/security), the
 * client address that of the current request (mj-zana/http), and the
 * correlation id that of the request, command or job. Never put secrets or
 * more personal data than needed in $details: entries cannot be changed.
 */
final readonly class AuditLog
{
    /**
     * @param (Closure(): ?string)|null $actor
     * @param (Closure(): ?string)|null $clientIp
     * @param (Closure(): ?string)|null $correlationId
     */
    public function __construct(
        private AuditLogStore $store,
        private ?Closure $actor = null,
        private ?Closure $clientIp = null,
        private ?Closure $correlationId = null,
    ) {
    }

    /**
     * @param array<string, mixed> $details
     * @param string|null $actor Who did it; the signed-in user when null
     */
    public function record(string $action, ?string $subject = null, array $details = [], ?string $actor = null): AuditEntry
    {
        return $this->store->append(
            $action,
            $actor ?? ($this->actor === null ? null : ($this->actor)()),
            $subject,
            $this->clientIp === null ? null : ($this->clientIp)(),
            $this->correlationId === null ? null : ($this->correlationId)(),
            $details,
        );
    }

    /**
     * Newest first.
     *
     * @return list<AuditEntry>
     */
    public function entries(?string $action = null, ?string $actor = null, ?string $subject = null, int $limit = 50): array
    {
        return $this->store->entries($action, $actor, $subject, $limit);
    }
}
