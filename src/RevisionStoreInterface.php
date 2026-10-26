<?php

declare(strict_types=1);

namespace Zana\Audit;

interface RevisionStoreInterface
{
    public function add(Revision $revision): void;

    /**
     * Newest first.
     *
     * @return list<Revision>
     */
    public function history(string $type, string $recordId, string $locale): array;

    public function find(string $type, string $recordId, string $locale, int $version): ?Revision;
}
