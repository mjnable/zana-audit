<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Database\ConnectionInterface;

/**
 * The security audit log's table (FE-58, ADR-030). Append-only: there is no
 * update and no delete, except prune() for a retention limit, from the
 * oldest end. The database user can also be denied UPDATE and DELETE on it.
 *
 * With $chain, each entry stores the hash of the previous one and its own,
 * so an edited, inserted or removed entry breaks the chain, which verify()
 * finds. Appends then go one at a time: each first updates the head row,
 * which holds the last sequence and hash, so concurrent appends wait for it.
 */
final class AuditLogStore
{
    public const string TABLE = 'audit_log';

    private const int PAGE = 1000;

    /** @var \Closure(): \DateTimeImmutable */
    private \Closure $clock;

    /**
     * @param (\Closure(): \DateTimeImmutable)|null $clock
     */
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly string $table = self::TABLE,
        private readonly bool $chain = false,
        ?\Closure $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): \DateTimeImmutable => new \DateTimeImmutable();
    }

    public function chained(): bool
    {
        return $this->chain;
    }

    /**
     * @param array<string, mixed> $details Nothing secret: entries cannot be changed
     */
    public function append(string $action, ?string $actor = null, ?string $subject = null, ?string $clientIp = null, ?string $correlationId = null, array $details = []): AuditEntry
    {
        $row = [
            'occurred_at' => ($this->clock)()->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z'),
            'action' => $action,
            'actor' => $actor,
            'subject' => $subject,
            'client_ip' => $clientIp === '' ? null : $clientIp,
            'correlation_id' => $correlationId,
            'details' => json_encode($details, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION),
        ];

        if (!$this->chain) {
            $this->connection->table($this->table)->insert($row);

            return self::entry($row);
        }

        return $this->connection->transaction(function (ConnectionInterface $tx) use ($row): AuditEntry {
            $head = "{$this->table}_head";
            $tx->table($head)->upsert(['id' => 1, 'sequence' => 0, 'last_hash' => null], uniqueBy: ['id'], update: []);
            // A write first: it locks the head row (the database on SQLite) until the commit.
            $tx->table($head)->where('id', 1)->increment('sequence');
            $state = $tx->table($head)->where('id', 1)->first();
            $sequence = (int) ($state['sequence'] ?? 0);
            $previous = is_string($state['last_hash'] ?? null) ? $state['last_hash'] : null;

            $row += ['sequence' => $sequence, 'previous_hash' => $previous, 'hash' => self::hash($previous, $sequence, $row)];
            $tx->table($this->table)->insert($row);
            $tx->table($head)->where('id', 1)->update(['last_hash' => $row['hash']]);

            return self::entry($row);
        });
    }

    /**
     * Newest first, filtered by action, actor and subject when given.
     *
     * @return list<AuditEntry>
     */
    public function entries(?string $action = null, ?string $actor = null, ?string $subject = null, int $limit = 50): array
    {
        $query = $this->connection->table($this->table)->orderBy('id', 'desc')->limit($limit);
        foreach (['action' => $action, 'actor' => $actor, 'subject' => $subject] as $column => $value) {
            if ($value !== null) {
                $query->where($column, $value);
            }
        }

        return array_map(self::entry(...), $query->get());
    }

    /**
     * Check the hash chain: every entry's hash, that each follows the previous
     * one without a gap, and that the last is the head's. The oldest remaining
     * entry is the anchor, as prune() removes entries from the oldest end.
     *
     * @param int|null $last Only the newest $last entries (check's quick look)
     */
    public function verify(?int $last = null): ChainReport
    {
        $after = null;
        if ($last !== null) {
            $start = $this->connection->table($this->table)->whereNotNull('sequence')->orderBy('sequence', 'desc')->limit(1)->offset($last)->value('sequence');
            $after = is_numeric($start) ? (int) $start : null;
        }

        $checked = 0;
        $previous = null;   // [sequence, hash] of the entry before
        while (true) {
            $query = $this->connection->table($this->table)->whereNotNull('sequence')->orderBy('sequence')->limit(self::PAGE);
            if ($after !== null) {
                $query->where('sequence', '>', $after);
            }
            $rows = $query->get();
            foreach ($rows as $row) {
                $sequence = (int) $row['sequence'];
                $stored = is_string($row['previous_hash'] ?? null) ? $row['previous_hash'] : null;
                if ($previous === null && $sequence === 1 && $stored !== null) {
                    return new ChainReport(false, $checked, $sequence, 'The first entry names a previous entry.');
                }
                if ($previous !== null && $sequence !== $previous[0] + 1) {
                    return new ChainReport(false, $checked, $previous[0] + 1, 'An entry is missing: sequence ' . ($previous[0] + 1) . ' is not in the log.');
                }
                if ($previous !== null && $stored !== $previous[1]) {
                    return new ChainReport(false, $checked, $sequence, 'The entry does not follow the one before it.');
                }
                if (!hash_equals(self::hash($stored, $sequence, $row), (string) ($row['hash'] ?? ''))) {
                    return new ChainReport(false, $checked, $sequence, 'The entry was changed after it was written.');
                }
                $previous = [$sequence, (string) $row['hash']];
                $after = $sequence;
                $checked++;
            }
            if (count($rows) < self::PAGE) {
                break;
            }
        }

        $head = $this->connection->table("{$this->table}_head")->where('id', 1)->first();
        if ($previous !== null && $head !== null && ((int) $head['sequence'] !== $previous[0] || $head['last_hash'] !== $previous[1])) {
            return new ChainReport(false, $checked, $previous[0] + 1, 'The newest entries are missing: the chain ends at ' . $previous[0] . ', its head at ' . (int) $head['sequence'] . '.');
        }

        return new ChainReport(true, $checked);
    }

    /**
     * Delete the entries older than $before (a retention limit).
     *
     * @return int The entries deleted
     */
    public function prune(\DateTimeImmutable $before): int
    {
        return $this->connection->table($this->table)
            ->where('occurred_at', '<', $before->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z'))
            ->delete();
    }

    /**
     * @return array{entries: int, chained: bool, oldest: string|null, newest: string|null}
     */
    public function counts(): array
    {
        $oldest = $this->connection->table($this->table)->orderBy('id')->value('occurred_at');
        $newest = $this->connection->table($this->table)->orderBy('id', 'desc')->value('occurred_at');

        return [
            'entries' => $this->connection->table($this->table)->count(),
            'chained' => $this->chain,
            'oldest' => is_string($oldest) ? $oldest : null,
            'newest' => is_string($newest) ? $newest : null,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hash(?string $previous, int $sequence, array $row): string
    {
        return hash('sha256', json_encode([
            $previous,
            $sequence,
            $row['occurred_at'] ?? null,
            $row['action'] ?? null,
            $row['actor'] ?? null,
            $row['subject'] ?? null,
            $row['client_ip'] ?? null,
            $row['correlation_id'] ?? null,
            $row['details'] ?? null,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function entry(array $row): AuditEntry
    {
        $details = is_string($row['details'] ?? null) ? json_decode($row['details'], true) : [];
        $text = static fn (string $key): ?string => is_scalar($row[$key] ?? null) ? (string) $row[$key] : null;

        return new AuditEntry(
            (string) $row['occurred_at'],
            (string) $row['action'],
            $text('actor'),
            $text('subject'),
            $text('client_ip'),
            $text('correlation_id'),
            is_array($details) ? $details : [],
            is_numeric($row['id'] ?? null) ? (int) $row['id'] : null,
            is_numeric($row['sequence'] ?? null) ? (int) $row['sequence'] : null,
            $text('previous_hash'),
            $text('hash'),
        );
    }
}
