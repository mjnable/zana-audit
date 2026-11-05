<?php

declare(strict_types=1);

namespace Zana\Audit\Console;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Style\SymfonyStyle;
use Zana\Audit\AuditLogMigration;
use Zana\Console\Command;
use Zana\Core\ApplicationInterface;
use Zana\Core\ConsoleScript;

/**
 * audit:install-log: writes database/migrations/<date>_create_audit_log_tables.php,
 * a migration that returns AuditLogMigration. Run migrate afterwards.
 */
#[AsCommand(name: 'audit:install-log', description: 'Write the migration of the security audit log tables')]
final class InstallLogCommand extends Command
{
    private const string STUB = <<<'PHP'
        <?php

        declare(strict_types=1);

        // The security audit log tables of mj-zana/audit. Pass the table name if audit.log.table is set.
        return new \Zana\Audit\AuditLogMigration();

        PHP;

    public function handle(ApplicationInterface $application, SymfonyStyle $io): int
    {
        $folder = $application->path('database', 'migrations');
        foreach (glob("{$folder}/*_create_audit_log_tables.php") ?: [] as $existing) {
            $io->writeln('The audit log migration exists: ' . basename($existing) . '.');

            return self::SUCCESS;
        }
        if (!is_dir($folder) && !mkdir($folder, 0777, true) && !is_dir($folder)) {
            $io->error("Cannot create {$folder}.");

            return self::FAILURE;
        }

        $file = $folder . '/' . gmdate('Y_m_d_His') . '_create_audit_log_tables.php';
        file_put_contents($file, self::STUB);
        $io->success('Wrote ' . basename($file) . ' (' . AuditLogMigration::class . '). Run ' . ConsoleScript::command('migrate') . '.');

        return self::SUCCESS;
    }
}
