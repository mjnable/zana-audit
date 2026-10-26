<?php

declare(strict_types=1);

namespace Zana\Audit;

/**
 * Revisions in memory, for tests.
 */
final class InMemoryRevisionStore implements RevisionStoreInterface
{
    /** @var list<Revision> */
    private array $revisions = [];

    public function add(Revision $revision): void
    {
        $this->revisions[] = $revision;
    }

    public function history(string $type, string $recordId, string $locale): array
    {
        $matching = array_values(array_filter(
            $this->revisions,
            static fn (Revision $r): bool => $r->type === $type && $r->recordId === $recordId && $r->locale === $locale,
        ));
        usort($matching, static fn (Revision $a, Revision $b): int => $b->version <=> $a->version);

        return $matching;
    }

    public function find(string $type, string $recordId, string $locale, int $version): ?Revision
    {
        foreach ($this->history($type, $recordId, $locale) as $revision) {
            if ($revision->version === $version) {
                return $revision;
            }
        }

        return null;
    }
}
