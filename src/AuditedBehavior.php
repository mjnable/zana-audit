<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Mediator\PipelineBehavior;

/**
 * Records #[Audited] commands in the security audit log once their handler
 * has returned (FE-58). A handler that throws records nothing. Add it to
 * mediator.behaviors, after the validation behaviour.
 */
final readonly class AuditedBehavior implements PipelineBehavior
{
    public function __construct(private AuditLog $log)
    {
    }

    public function handle(object $message, \Closure $next): mixed
    {
        $attributes = (new \ReflectionClass($message))->getAttributes(Audited::class);
        if ($attributes === []) {
            return $next($message);
        }
        $audited = $attributes[0]->newInstance();
        // Read before the handler runs: a missing property fails before anything is done.
        $details = [];
        foreach ($audited->details as $property) {
            $details[$property] = self::value(self::read($message, $property));
        }
        $subject = $audited->subject === null ? null : self::value(self::read($message, $audited->subject));

        $result = $next($message);
        $this->log->record($audited->action, $subject === null ? null : (is_scalar($subject) ? (string) $subject : json_encode($subject, JSON_THROW_ON_ERROR)), $details);

        return $result;
    }

    private static function read(object $message, string $property): mixed
    {
        if (!property_exists($message, $property)) {
            throw new AuditException(sprintf('%s has no property "%s", named in its #[Audited].', $message::class, $property));
        }

        return (new \ReflectionProperty($message, $property))->getValue($message);
    }

    /**
     * Scalars, null and lists of them as they are; enums, dates and Stringables as text; other objects by type only.
     */
    private static function value(mixed $value): mixed
    {
        return match (true) {
            $value === null, is_scalar($value) => $value,
            $value instanceof \BackedEnum => $value->value,
            $value instanceof \UnitEnum => $value->name,
            $value instanceof \DateTimeInterface => $value->format(\DateTimeInterface::ATOM),
            $value instanceof \Stringable => (string) $value,
            is_array($value) => array_map(self::value(...), $value),
            default => '(' . get_debug_type($value) . ')',
        };
    }
}
