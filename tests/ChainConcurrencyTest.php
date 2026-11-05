<?php

declare(strict_types=1);

namespace Zana\Audit\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zana\Audit\AuditLogMigration;
use Zana\Audit\AuditLogStore;
use Zana\Database\ConnectionFactory;

/**
 * Four processes append to the chained log at the same moment: every entry
 * gets its own sequence, without a gap, and the chain verifies.
 */
final class ChainConcurrencyTest extends TestCase
{
    /**
     * @return array<string, array{string}>
     */
    public static function drivers(): array
    {
        return Databases::names();
    }

    #[DataProvider('drivers')]
    public function testConcurrentAppendsKeepOneChain(string $driver): void
    {
        $file = $driver === 'sqlite' ? str_replace('\\', '/', sys_get_temp_dir()) . '/zana-audit-chain-' . bin2hex(random_bytes(4)) . '.sqlite' : null;
        $settings = $file === null ? Databases::settings($driver) : ['driver' => 'sqlite', 'database' => $file];
        if (is_string($settings)) {
            $this->markTestSkipped($settings);
        }
        $db = ConnectionFactory::create($settings);
        (new AuditLogMigration())->down($db->schema());
        (new AuditLogMigration())->up($db->schema());

        $php = [PHP_BINARY, '-d', 'xdebug.mode=off'];
        exec(escapeshellarg(PHP_BINARY) . " -r \"echo extension_loaded('pdo_{$driver}') ? 1 : 0;\"", $loaded);
        if ($driver !== 'sqlite' && ($loaded[0] ?? '1') === '0') {
            array_push($php, '-d', "extension=pdo_{$driver}");
        }
        $start = (string) (microtime(true) + 1.5);
        $workers = [];
        $pipes = [];
        foreach (range(1, 4) as $_) {
            $worker = proc_open([...$php, __DIR__ . '/append-worker.php', json_encode($settings, JSON_THROW_ON_ERROR), $start, '25'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes[]);
            $this->assertIsResource($worker);
            $workers[] = $worker;
        }
        foreach ($workers as $i => $worker) {
            $output = (string) stream_get_contents($pipes[$i][1]);
            $errors = (string) stream_get_contents($pipes[$i][2]);
            $this->assertSame(0, proc_close($worker), "{$output}\n{$errors}");
            $this->assertSame('ok', $output);
        }

        $store = new AuditLogStore($db, chain: true);
        $this->assertSame(100, $db->table(AuditLogStore::TABLE)->count());
        $this->assertSame(range(1, 100), array_map('intval', array_column($db->table(AuditLogStore::TABLE)->orderBy('sequence')->get(), 'sequence')));
        $report = $store->verify();
        $this->assertTrue($report->intact, (string) $report->problem);
        $this->assertSame(100, $report->checked);

        if ($file !== null) {
            unset($db, $store);
            @unlink($file);
        }
    }
}
