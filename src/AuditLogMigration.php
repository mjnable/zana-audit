<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Database\Migration\Migration;
use Zana\Database\Schema\Blueprint;
use Zana\Database\Schema\Schema;

/**
 * The security audit log tables (2.15): the entries, and one head row that
 * holds the last sequence and hash of the chain. Written by
 * `audit:install-log`.
 */
final class AuditLogMigration extends Migration
{
    public function __construct(private readonly string $table = AuditLogStore::TABLE)
    {
    }

    public function up(Schema $schema): void
    {
        $schema->create($this->table, static function (Blueprint $t): void {
            $t->id();
            $t->bigInteger('sequence')->nullable()->unique();
            $t->string('occurred_at', 32);
            $t->string('action', 100);
            $t->string('actor', 190)->nullable();
            $t->string('subject', 190)->nullable();
            $t->string('client_ip', 45)->nullable();
            $t->string('correlation_id', 128)->nullable();
            $t->text('details');
            $t->string('previous_hash', 64)->nullable();
            $t->string('hash', 64)->nullable();
        });
        $table = $this->table;
        $schema->create("{$table}_head", static function (Blueprint $t): void {
            $t->integer('id')->primary();
            $t->bigInteger('sequence')->default(0);
            $t->string('last_hash', 64)->nullable();
        });
    }

    public function down(Schema $schema): void
    {
        $schema->dropIfExists("{$this->table}_head");
        $schema->dropIfExists($this->table);
    }
}
