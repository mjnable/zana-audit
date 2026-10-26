<?php

declare(strict_types=1);

namespace Zana\Audit;

/**
 * One saved version of a record in a locale.
 */
final readonly class Revision
{
    /**
     * @param array<string, mixed> $data The record's content at that version
     */
    public function __construct(
        public string $type,
        public string $recordId,
        public string $locale,
        public int $version,
        public array $data,
        public ?string $author,
        public int $createdAt,
        public ?string $note = null,
    ) {
    }

    /**
     * The fields that differ from another revision, with both values.
     *
     * @return array<string, array{mixed, mixed}> field => [this value, other value]
     */
    public function diff(self $other): array
    {
        $changes = [];
        foreach (array_unique([...array_keys($this->data), ...array_keys($other->data)]) as $field) {
            $mine = $this->data[$field] ?? null;
            $theirs = $other->data[$field] ?? null;
            if ($mine !== $theirs) {
                $changes[$field] = [$mine, $theirs];
            }
        }

        return $changes;
    }
}
