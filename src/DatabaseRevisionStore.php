<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Database\ConnectionInterface;
use Zana\Database\Schema\Blueprint;

/**
 * Revisions in a table of the application's database. Create it in a
 * migration with DatabaseRevisionStore::createTable().
 */
final readonly class DatabaseRevisionStore implements RevisionStoreInterface
{
    public function __construct(
        private ConnectionInterface $connection,
        private string $table = 'audit_revisions',
    ) {
    }

    public static function createTable(ConnectionInterface $connection, string $table = 'audit_revisions'): void
    {
        $connection->schema()->create($table, static function (Blueprint $t): void {
            $t->id();
            $t->string('type', 100);
            $t->string('record_id', 100);
            $t->string('locale', 16);
            $t->integer('version');
            $t->text('data');
            $t->string('author', 190)->nullable();
            $t->integer('created_at');
            $t->string('note')->nullable();
            $t->unique(['type', 'record_id', 'locale', 'version']);
        });
    }

    public function add(Revision $revision): void
    {
        $this->connection->table($this->table)->insert([
            'type' => $revision->type,
            'record_id' => $revision->recordId,
            'locale' => $revision->locale,
            'version' => $revision->version,
            'data' => json_encode($revision->data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
            'author' => $revision->author,
            'created_at' => $revision->createdAt,
            'note' => $revision->note,
        ]);
    }

    public function history(string $type, string $recordId, string $locale): array
    {
        $rows = $this->connection->table($this->table)
            ->where('type', $type)->where('record_id', $recordId)->where('locale', $locale)
            ->orderBy('version', 'desc')
            ->get();

        return array_map(self::revision(...), $rows);
    }

    public function find(string $type, string $recordId, string $locale, int $version): ?Revision
    {
        $row = $this->connection->table($this->table)
            ->where('type', $type)->where('record_id', $recordId)->where('locale', $locale)->where('version', $version)
            ->first();

        return $row === null ? null : self::revision($row);
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function revision(array $row): Revision
    {
        $data = json_decode((string) $row['data'], true, flags: JSON_THROW_ON_ERROR);
        /** @var array<string, mixed> $data */
        $data = is_array($data) ? $data : [];

        return new Revision(
            (string) $row['type'],
            (string) $row['record_id'],
            (string) $row['locale'],
            (int) $row['version'],
            $data,
            $row['author'] === null ? null : (string) $row['author'],
            (int) $row['created_at'],
            $row['note'] === null ? null : (string) $row['note'],
        );
    }
}
