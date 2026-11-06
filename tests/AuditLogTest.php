<?php

declare(strict_types=1);

namespace Zana\Audit\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zana\Audit\AuditEntry;
use Zana\Audit\AuditException;
use Zana\Audit\Audited;
use Zana\Audit\AuditedBehavior;
use Zana\Audit\AuditLog;
use Zana\Audit\AuditLogMigration;
use Zana\Audit\AuditLogStore;
use Zana\Audit\SecurityEventsRecorder;
use Zana\Database\ConnectionFactory;
use Zana\Database\ConnectionInterface;
use Zana\Events\EventDispatcher;
use Zana\Events\ListenerProvider;
use Zana\Security\Event\PasswordResetRequested;
use Zana\Security\Event\SecurityEvent;
use Zana\Security\Event\SignedOut;
use Zana\Security\Event\SignInFailed;
use Zana\Security\Event\SignInSucceeded;
use Zana\Security\Event\RecoveryCodeUsed;
use Zana\Security\Event\TwoFactorFailed;

enum Currency: string
{
    case Cdf = 'CDF';
    case Usd = 'USD';
}

#[Audited('order.refund', subject: 'orderId', details: ['orderId', 'amount', 'currency'])]
final readonly class RefundOrder
{
    public function __construct(
        public string $orderId,
        public int $amount,
        public Currency $currency,
        public string $cardNumber,   // not listed: never recorded
    ) {
    }
}

#[Audited('order.refund', details: ['missing'])]
final readonly class BrokenAudit
{
}

/**
 * FE-58, ADR-030, on every database available here: an append-only log of
 * sensitive actions, with an optional hash chain that finds edited, removed
 * and inserted entries, retention, #[Audited] commands and security events.
 */
final class AuditLogTest extends TestCase
{
    private ConnectionInterface $db;

    private string $now = '2026-11-05 10:00:00';

    /**
     * @return array<string, array{string}>
     */
    public static function drivers(): array
    {
        return Databases::names();
    }

    #[DataProvider('drivers')]
    public function testEntriesAreAppendedAndListedNewestFirst(string $driver): void
    {
        $log = new AuditLog($this->store($driver), static fn (): string => 'staff-7', static fn (): string => '198.51.100.7', static fn (): string => 'req-42');

        $log->record('payout.account_changed', 'organizer:12', ['bank' => 'Rawbank']);
        $log->record('order.refund', 'order:9', ['amount' => 2500], actor: 'staff-9');

        $entries = $log->entries();
        $this->assertSame(['order.refund', 'payout.account_changed'], array_map(static fn (AuditEntry $e): string => $e->action, $entries));
        $this->assertSame(['staff-9', 'order:9', '198.51.100.7', 'req-42', ['amount' => 2500]], [$entries[0]->actor, $entries[0]->subject, $entries[0]->clientIp, $entries[0]->correlationId, $entries[0]->details]);
        $this->assertSame('2026-11-05T10:00:00.000000Z', $entries[0]->occurredAt);
        $this->assertSame(['payout.account_changed'], array_map(static fn (AuditEntry $e): string => $e->action, $log->entries(actor: 'staff-7')));
        $this->assertNull($entries[0]->hash, 'not chained');
    }

    #[DataProvider('drivers')]
    public function testTheChainFindsChangedRemovedAndInsertedEntries(string $driver): void
    {
        $store = $this->store($driver, chain: true);
        foreach (range(1, 5) as $i) {
            $store->append('order.refund', 'staff-7', "order:{$i}", details: ['amount' => $i * 100]);
        }
        $this->assertEquals(new \Zana\Audit\ChainReport(true, 5), $store->verify());
        $this->assertSame([5, 4], array_map(static fn (AuditEntry $e): ?int => $e->sequence, $store->entries(limit: 2)));

        $table = $this->db->table(AuditLogStore::TABLE);
        $table->where('sequence', 3)->update(['details' => '{"amount":1}']);
        $report = $store->verify();
        $this->assertSame([false, 3, 'The entry was changed after it was written.', 2], [$report->intact, $report->brokenAt, $report->problem, $report->checked]);
        $this->db->table(AuditLogStore::TABLE)->where('sequence', 3)->update(['details' => '{"amount":300}']);
        $this->assertTrue($store->verify()->intact, 'restored');

        $this->db->table(AuditLogStore::TABLE)->where('sequence', 4)->delete();
        $this->assertSame([false, 4], [$store->verify()->intact, $store->verify()->brokenAt], 'a gap');
    }

    #[DataProvider('drivers')]
    public function testRemovingTheNewestEntriesIsFoundThroughTheHead(string $driver): void
    {
        $store = $this->store($driver, chain: true);
        foreach (range(1, 3) as $i) {
            $store->append('security.sign_in', "user-{$i}");
        }
        $this->db->table(AuditLogStore::TABLE)->where('sequence', 3)->delete();

        $report = $store->verify();
        $this->assertFalse($report->intact);
        $this->assertStringContainsString('The newest entries are missing', (string) $report->problem);
    }

    #[DataProvider('drivers')]
    public function testPruningKeepsTheRestOfTheChainVerifiable(string $driver): void
    {
        $store = $this->store($driver, chain: true);
        $this->now = '2025-01-10 08:00:00';
        $store->append('security.sign_in', 'user-1');
        $store->append('security.sign_in', 'user-2');
        $this->now = '2026-11-05 10:00:00';
        $store->append('security.sign_in', 'user-3');

        $this->assertSame(2, $store->prune(new \DateTimeImmutable('2026-01-01 00:00:00', new \DateTimeZone('UTC'))));
        $this->assertEquals(new \Zana\Audit\ChainReport(true, 1), $store->verify(), 'the oldest remaining entry anchors the chain');
        $store->append('security.sign_in', 'user-4');
        $this->assertTrue($store->verify()->intact);
        $this->assertTrue($store->verify(last: 1)->intact, 'check looks at the newest entries only');
    }

    #[DataProvider('drivers')]
    public function testSecurityEventsAreRecorded(string $driver): void
    {
        $recorder = new SecurityEventsRecorder($this->store($driver), static fn (): string => 'req-7');
        $events = new EventDispatcher((new ListenerProvider())->listen(SecurityEvent::class, $recorder));

        $events->dispatch(new SignInFailed('ada@example.com', SignInFailed::INVALID_CREDENTIALS, '198.51.100.7'));
        $events->dispatch(new SignInSucceeded('7', '198.51.100.7'));
        $events->dispatch(new PasswordResetRequested('7'));
        $events->dispatch(new SignedOut('7', '198.51.100.7'));
        $events->dispatch(new TwoFactorFailed('7', TwoFactorFailed::INVALID_CODE, '198.51.100.7'));
        $events->dispatch(new RecoveryCodeUsed('7', 9, '198.51.100.7'));

        $rows = array_reverse(array_map(static fn (AuditEntry $e): array => [$e->action, $e->actor, $e->subject, $e->clientIp, $e->details], (new AuditLog($this->storeOn()))->entries()));
        $this->assertSame([
            ['security.sign_in_failed', null, null, '198.51.100.7', ['login' => 'ada@example.com', 'reason' => 'invalid_credentials']],
            ['security.sign_in', '7', 'user:7', '198.51.100.7', ['method' => 'session']],
            ['security.password_reset_requested', null, 'user:7', null, []],
            ['security.sign_out', '7', 'user:7', '198.51.100.7', []],
            ['security.two_factor_failed', null, 'user:7', '198.51.100.7', ['reason' => 'invalid_code']],
            ['security.recovery_code_used', '7', 'user:7', '198.51.100.7', ['remaining' => 9]],
        ], $rows);
        $this->assertSame('req-7', $this->storeOn()->entries(limit: 1)[0]->correlationId);
    }

    public function testAuditedCommandsRecordOnlyTheListedFieldsAfterTheHandlerSucceeds(): void
    {
        $log = new AuditLog($this->store('sqlite'), static fn (): string => 'staff-7');
        $behavior = new AuditedBehavior($log);

        $this->assertSame('refunded', $behavior->handle(new RefundOrder('o-9', 2500, Currency::Usd, '4111111111111111'), static fn (): string => 'refunded'));
        try {
            $behavior->handle(new RefundOrder('o-10', 100, Currency::Cdf, '4111111111111111'), static fn () => throw new \RuntimeException('The provider refused.'));
        } catch (\RuntimeException) {
        }
        $this->assertSame('plain', $behavior->handle(new \stdClass(), static fn (): string => 'plain'), 'unmarked commands pass through');

        $entries = $log->entries();
        $this->assertCount(1, $entries, 'a failed refund is not recorded');
        $this->assertSame(['order.refund', 'staff-7', 'o-9', ['orderId' => 'o-9', 'amount' => 2500, 'currency' => 'USD']], [$entries[0]->action, $entries[0]->actor, $entries[0]->subject, $entries[0]->details]);
        $this->assertStringNotContainsString('4111', (string) json_encode($this->db->table(AuditLogStore::TABLE)->get()));

        $this->expectException(AuditException::class);
        $this->expectExceptionMessage('has no property "missing"');
        $behavior->handle(new BrokenAudit(), static fn (): string => 'never');
    }

    private function store(string $driver, bool $chain = false): AuditLogStore
    {
        $settings = Databases::settings($driver);
        if (is_string($settings)) {
            $this->markTestSkipped($settings);
        }
        $this->db = ConnectionFactory::create($settings);
        (new AuditLogMigration())->down($this->db->schema());
        (new AuditLogMigration())->up($this->db->schema());

        return $this->storeOn($chain);
    }

    private function storeOn(bool $chain = false): AuditLogStore
    {
        return new AuditLogStore($this->db, chain: $chain, clock: fn (): \DateTimeImmutable => new \DateTimeImmutable($this->now, new \DateTimeZone('UTC')));
    }
}
