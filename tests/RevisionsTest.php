<?php

declare(strict_types=1);

namespace Zana\Audit\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Audit\AuditException;
use Zana\Audit\DatabaseRevisionStore;
use Zana\Audit\InMemoryRevisionStore;
use Zana\Audit\Revision;
use Zana\Audit\Revisions;
use Zana\Audit\RevisionStoreInterface;
use Zana\Database\ConnectionFactory;

final class RevisionsTest extends TestCase
{
    private int $now = 1_800_000_000;

    public function testVersionsAuthorsAndHistoryPerLocale(): void
    {
        $author = 'ada';
        $revisions = new Revisions(new InMemoryRevisionStore(), function () use (&$author): string {
            return $author;
        }, fn (): int => $this->now);

        $revisions->record('post', '42', 'fr', ['title' => 'Lancement']);
        $author = 'bob';
        $this->now += 60;
        $second = $revisions->record('post', '42', 'fr', ['title' => 'Le lancement']);
        $revisions->record('post', '42', 'en', ['title' => 'Launch']);

        $history = $revisions->history('post', '42', 'fr');
        $this->assertSame([2, 1], array_map(static fn (Revision $r): int => $r->version, $history));
        $this->assertSame(['bob', 'ada'], array_map(static fn (Revision $r): ?string => $r->author, $history));
        $this->assertSame($this->now, $second->createdAt);
        $this->assertSame(['title' => ['Le lancement', 'Lancement']], $history[0]->diff($history[1]));
        $this->assertSame(1, $revisions->latest('post', '42', 'en')?->version, 'locales are separate');
    }

    public function testRecordingIdenticalContentDoesNothing(): void
    {
        $revisions = new Revisions(new InMemoryRevisionStore());
        $first = $revisions->record('post', '1', 'en', ['title' => 'Hi']);

        $this->assertSame($first, $revisions->record('post', '1', 'en', ['title' => 'Hi']));
        $this->assertCount(1, $revisions->history('post', '1', 'en'));
    }

    public function testRestoreRecordsANewVersion(): void
    {
        $revisions = new Revisions(new InMemoryRevisionStore());
        $revisions->record('page', 'about', 'en', ['body' => 'v1']);
        $revisions->record('page', 'about', 'en', ['body' => 'v2']);

        $this->assertSame(['body' => 'v1'], $revisions->restore('page', 'about', 'en', 1));
        $latest = $revisions->latest('page', 'about', 'en');
        $this->assertSame([3, 'Restored version 1'], [$latest?->version, $latest?->note]);

        $this->expectException(AuditException::class);
        $revisions->restore('page', 'about', 'en', 9);
    }

    public function testTheDatabaseStore(): void
    {
        $connection = ConnectionFactory::create(['driver' => 'sqlite', 'database' => ':memory:']);
        DatabaseRevisionStore::createTable($connection);
        $store = new DatabaseRevisionStore($connection);
        $this->exercise($store);
    }

    private function exercise(RevisionStoreInterface $store): void
    {
        $revisions = new Revisions($store, static fn (): string => 'ada', fn (): int => $this->now);
        $revisions->record('post', '7', 'fr', ['title' => 'Élan', 'tags' => ['a', 'b']]);
        $revisions->record('post', '7', 'fr', ['title' => 'Élan 2', 'tags' => ['a']], 'typo');

        $history = $revisions->history('post', '7', 'fr');
        $this->assertSame([2, 1], array_map(static fn (Revision $r): int => $r->version, $history));
        $this->assertSame(['title' => 'Élan', 'tags' => ['a', 'b']], $store->find('post', '7', 'fr', 1)?->data);
        $this->assertSame(['typo', 'ada', $this->now], [$history[0]->note, $history[0]->author, $history[0]->createdAt]);
        $this->assertNull($store->find('post', '7', 'en', 1));
    }
}
