<?php

declare(strict_types=1);

namespace Zana\Audit;

use Attribute;

/**
 * Records a mediator command in the security audit log after its handler
 * succeeds; enforced by AuditedBehavior (in mediator.behaviors).
 *
 *     #[Audited('order.refund', subject: 'orderId', details: ['orderId', 'amount'])]
 *     final readonly class RefundOrder { ... }
 *
 * Only the properties named in $details are recorded, so nothing secret or
 * personal slips into an entry that cannot be changed.
 */
#[Attribute(Attribute::TARGET_CLASS)]
final readonly class Audited
{
    /**
     * @param string $action The entry's action, such as "order.refund"
     * @param string|null $subject The property whose value is the entry's subject
     * @param list<string> $details The properties recorded as details
     */
    public function __construct(
        public string $action,
        public ?string $subject = null,
        public array $details = [],
    ) {
    }
}
