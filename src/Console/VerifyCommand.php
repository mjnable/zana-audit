<?php

declare(strict_types=1);

namespace Zana\Audit\Console;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Style\SymfonyStyle;
use Zana\Audit\AuditLogStore;
use Zana\Console\Command;

/**
 * audit:verify: checks the whole hash chain of the security audit log
 * (audit.log.chain). Exit code 1 when it is broken.
 */
#[AsCommand(name: 'audit:verify', description: 'Check the hash chain of the security audit log')]
final class VerifyCommand extends Command
{
    public function handle(AuditLogStore $store, SymfonyStyle $io): int
    {
        if (!$store->chained()) {
            $io->writeln('The audit log is not chained (audit.log.chain is false): there is nothing to verify.');

            return self::SUCCESS;
        }

        $report = $store->verify();
        if (!$report->intact) {
            $io->error("The audit log chain is broken at entry {$report->brokenAt}: {$report->problem} ({$report->checked} entries before it are intact.)");

            return self::FAILURE;
        }
        $io->success("The audit log chain is intact: {$report->checked} entries checked.");

        return self::SUCCESS;
    }
}
