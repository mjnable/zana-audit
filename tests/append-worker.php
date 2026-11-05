<?php

declare(strict_types=1);

// One process of ChainConcurrencyTest: waits until the shared start time, then appends $argv[3]
// entries to the chained audit log.

use Zana\Audit\AuditLogStore;
use Zana\Database\ConnectionFactory;

require dirname(__DIR__) . '/vendor/autoload.php';

$arguments = $_SERVER['argv'] ?? [];
assert(is_array($arguments) && is_string($arguments[1] ?? null) && is_string($arguments[2] ?? null) && is_string($arguments[3] ?? null));
$settings = json_decode($arguments[1], true, flags: JSON_THROW_ON_ERROR);
assert(is_array($settings));
$db = ConnectionFactory::create($settings);
if ($db->driver() === 'sqlite') {
    $db->execute('PRAGMA busy_timeout = 10000');
}
$store = new AuditLogStore($db, chain: true);

while (microtime(true) < (float) $arguments[2]) {
    usleep(1_000);
}
for ($i = 0; $i < (int) $arguments[3]; $i++) {
    $store->append('security.sign_in', 'user-' . getmypid(), details: ['n' => $i]);
}
echo 'ok';
