<?php

declare(strict_types=1);

namespace Zana\Audit\Console;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Style\SymfonyStyle;
use Zana\Audit\AuditEntry;
use Zana\Audit\AuditLogStore;
use Zana\Console\Command;

/**
 * audit:log [--action=] [--actor=] [--subject=] [--limit=20]: the newest
 * security audit log entries.
 */
#[AsCommand(name: 'audit:log', description: 'Show the newest security audit log entries')]
final class LogCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('action', null, InputOption::VALUE_REQUIRED, 'Only this action, e.g. security.sign_in_failed')
            ->addOption('actor', null, InputOption::VALUE_REQUIRED, 'Only this actor')
            ->addOption('subject', null, InputOption::VALUE_REQUIRED, 'Only this subject')
            ->addOption('limit', null, InputOption::VALUE_REQUIRED, 'How many entries', '20');
    }

    public function handle(AuditLogStore $store, InputInterface $input, SymfonyStyle $io): int
    {
        $option = static function (string $name) use ($input): ?string {
            $value = $input->getOption($name);

            return is_string($value) && $value !== '' ? $value : null;
        };
        $entries = $store->entries($option('action'), $option('actor'), $option('subject'), max(1, (int) $input->getOption('limit')));
        if ($entries === []) {
            $io->writeln('No audit log entries.');

            return self::SUCCESS;
        }

        $io->table(
            ['When (UTC)', 'Action', 'Actor', 'Subject', 'Client', 'Details'],
            array_map(static fn (AuditEntry $e): array => [
                substr($e->occurredAt, 0, 19),
                $e->action,
                $e->actor ?? '-',
                $e->subject ?? '-',
                $e->clientIp ?? '-',
                $e->details === [] ? '' : (string) json_encode($e->details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ], $entries),
        );

        return self::SUCCESS;
    }
}
