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
 * audit:spam (2.25, FE-63): the form posts refused by their spam rules over
 * the last days, by form and by rule, from security.spam_refused, so a rule
 * that refuses real messages is noticed and loosened. Neither text nor
 * client addresses are shown: a summary needs neither.
 */
#[AsCommand(name: 'audit:spam', description: 'Summarise the form posts refused as spam, by form and by rule')]
final class SpamCommand extends Command
{
    private const int LIMIT = 10000;

    protected function configure(): void
    {
        $this->addOption('days', null, InputOption::VALUE_REQUIRED, 'How many days back', '7');
    }

    public function handle(AuditLogStore $store, InputInterface $input, SymfonyStyle $io): int
    {
        $days = $input->getOption('days');
        if (!is_string($days) || !ctype_digit($days) || (int) $days < 1) {
            $io->error('--days must be a whole number of at least 1.');

            return self::FAILURE;
        }
        $entries = $store->since('security.spam_refused', new \DateTimeImmutable("-{$days} days"), self::LIMIT);
        if ($entries === []) {
            $io->writeln("No form post was refused as spam in the last {$days} day(s).");

            return self::SUCCESS;
        }

        $forms = [];
        $rules = [];
        foreach ($entries as $entry) {
            $form = self::form($entry);
            $forms[$form] ??= ['refusals' => 0, 'last' => $entry->occurredAt];
            $forms[$form]['refusals']++;
            $reasons = $entry->details['reasons'] ?? [];
            foreach (is_array($reasons) ? $reasons : [] as $reason) {
                $rule = is_string($reason) ? strtok($reason, ':') : false;
                $key = $form . "\0" . (is_string($rule) ? $rule : '?');
                $rules[$key] = ($rules[$key] ?? 0) + 1;
            }
        }
        ksort($forms);
        arsort($rules);

        $io->writeln(count($entries) . " form post(s) refused as spam in the last {$days} day(s)" . (count($entries) === self::LIMIT ? ' (the newest ' . self::LIMIT . ' read)' : '') . ':');
        $io->table(['Form', 'Refused', 'Last (UTC)'], array_map(
            static fn (string $form, array $row): array => [$form, (string) $row['refusals'], substr($row['last'], 0, 19)],
            array_keys($forms),
            $forms,
        ));
        $io->table(['Form', 'Rule', 'Times it found something'], array_map(
            static function (string $key, int $times): array {
                [$form, $rule] = explode("\0", $key, 2);

                return [$form, $rule, (string) $times];
            },
            array_keys($rules),
            $rules,
        ));
        $io->writeln('A rule that refuses real messages should be loosened: read the entries with audit:log --action=security.spam_refused.');

        return self::SUCCESS;
    }

    private static function form(AuditEntry $entry): string
    {
        return is_string($entry->subject) && str_starts_with($entry->subject, 'form:') ? substr($entry->subject, 5) : ($entry->subject ?? '?');
    }
}
