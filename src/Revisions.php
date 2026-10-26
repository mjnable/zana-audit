<?php

declare(strict_types=1);

namespace Zana\Audit;

use Closure;

/**
 * Content revisions (FE-37): record each published version of a record per
 * locale, show who changed what and when, and restore an earlier version.
 *
 *     $revisions->record('post', $post->id, 'fr', ['title' => $title, 'body' => $body]);
 *     $revisions->history('post', $post->id, 'fr');        // newest first
 *     $data = $revisions->restore('post', $post->id, 'fr', 3);
 *
 * Recording identical content again does nothing. The author is the
 * signed-in user when mj-zana/security is installed (registered scoped).
 */
final readonly class Revisions
{
    /** @var Closure(): int */
    private Closure $now;

    /**
     * @param (Closure(): ?string)|null $author The current author's identifier
     * @param (Closure(): int)|null $clock
     */
    public function __construct(
        private RevisionStoreInterface $store,
        private ?Closure $author = null,
        ?Closure $clock = null,
    ) {
        $this->now = $clock ?? static fn (): int => time();
    }

    /**
     * @param array<string, mixed> $data
     */
    public function record(string $type, string $recordId, string $locale, array $data, ?string $note = null, ?string $author = null): Revision
    {
        $latest = $this->latest($type, $recordId, $locale);
        if ($latest !== null && $latest->data === $data) {
            return $latest;
        }

        $revision = new Revision(
            $type,
            $recordId,
            $locale,
            $latest === null ? 1 : $latest->version + 1,
            $data,
            $author ?? ($this->author === null ? null : ($this->author)()),
            ($this->now)(),
            $note,
        );
        $this->store->add($revision);

        return $revision;
    }

    /**
     * @return list<Revision> newest first
     */
    public function history(string $type, string $recordId, string $locale): array
    {
        return $this->store->history($type, $recordId, $locale);
    }

    public function latest(string $type, string $recordId, string $locale): ?Revision
    {
        return $this->store->history($type, $recordId, $locale)[0] ?? null;
    }

    /**
     * The content of an earlier version, recorded again as the newest one
     * ("Restored version 3"). Save it to the record yourself.
     *
     * @return array<string, mixed>
     * @throws AuditException When the version does not exist
     */
    public function restore(string $type, string $recordId, string $locale, int $version): array
    {
        $revision = $this->store->find($type, $recordId, $locale, $version)
            ?? throw new AuditException("There is no version {$version} of {$type} {$recordId} in {$locale}.");
        $this->record($type, $recordId, $locale, $revision->data, "Restored version {$version}");

        return $revision->data;
    }
}
