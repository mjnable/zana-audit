<?php

declare(strict_types=1);

namespace Zana\Audit\Console;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Style\SymfonyStyle;
use Zana\Audit\AuditLogStore;
use Zana\Configuration\ConfigurationInterface;
use Zana\Console\Command;

/**
 * audit:prune: deletes the security audit log entries older than
 * audit.log.retention_days. Without that setting, entries are kept forever
 * and nothing is deleted. Schedule it daily.
 */
#[AsCommand(name: 'audit:prune', description: 'Delete the audit log entries older than audit.log.retention_days')]
final class PruneCommand extends Command
{
    public function handle(AuditLogStore $store, ConfigurationInterface $config, SymfonyStyle $io): int
    {
        $days = $config->get('audit.log.retention_days');
        if (!is_int($days) && !(is_string($days) && ctype_digit($days))) {
            $io->writeln('audit.log.retention_days is not set: audit log entries are kept forever.');

            return self::SUCCESS;
        }
        if ((int) $days < 1) {
            $io->error('audit.log.retention_days must be 1 or more.');

            return self::FAILURE;
        }

        $deleted = $store->prune(new \DateTimeImmutable("-{$days} days"));
        $io->writeln(sprintf('Deleted %d audit log entr%s older than %d days.', $deleted, $deleted === 1 ? 'y' : 'ies', (int) $days));

        return self::SUCCESS;
    }
}
