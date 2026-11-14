<?php

declare(strict_types=1);

namespace Zana\Audit\Inspection;

use Zana\Audit\AuditLogStore;
use Zana\Core\ApplicationInterface;
use Zana\Core\ConsoleScript;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;

/**
 * With audit.log.enabled (ADR-030): audit.log when the log's table cannot
 * be read, so security events would fail to be recorded; audit.chain when
 * the newest 1,000 entries of a chained log do not verify (audit:verify
 * checks them all). The store is given lazily.
 *
 * audit.retention (2.24.1): a warning when audit.log.retention_days is not
 * set, so entries, spam refusals among them, are kept forever without
 * anyone having chosen it; an error when it is set to something audit:prune
 * refuses.
 */
final readonly class AuditLogCheck implements ApplicationCheck
{
    /**
     * @param \Closure(): AuditLogStore $store
     */
    public function __construct(private \Closure $store, private bool $enabled = true)
    {
    }

    public function findings(ApplicationInterface $application): array
    {
        if (!$this->enabled) {
            return [];   // revisions only: the application does not keep a security audit log
        }

        return [...self::retention($application), ...$this->log()];
    }

    /**
     * @return list<Finding>
     */
    private static function retention(ApplicationInterface $application): array
    {
        $days = $application->config()->get('audit.log.retention_days');
        $prune = ConsoleScript::command('audit:prune');
        if ($days === null) {
            return [new Finding(
                'audit.retention',
                Severity::Warning,
                'Audit log entries are kept forever: audit.log.retention_days is not set.',
                hint: "Choose how long your obligations and investigations need, e.g. 'retention_days' => 730 in config/audit.php, and run {$prune} every day. Pruning removes the oldest entries; the chain stays verifiable from the oldest one kept.",
            )];
        }
        // As audit:prune reads it: a whole number, or its digits from the environment (APP_AUDIT__LOG__RETENTION_DAYS=730).
        $whole = is_int($days) || (is_string($days) && ctype_digit($days));
        if (!$whole || (int) $days < 1) {
            return [new Finding(
                'audit.retention',
                Severity::Error,
                'audit.log.retention_days is ' . json_encode($days) . ', not a whole number of days of at least 1, so '
                    . ($whole ? "{$prune} refuses to run." : "{$prune} takes it as not set and keeps every entry."),
                hint: 'Set it to a number of days, e.g. 730.',
            )];
        }

        return [];
    }

    /**
     * @return list<Finding>
     */
    private function log(): array
    {
        try {
            $store = ($this->store)();
            $store->counts();
        } catch (\Throwable $e) {
            return [new Finding(
                'audit.log',
                Severity::Error,
                'The security audit log cannot be read: ' . strtok($e->getMessage(), "\n"),
                hint: 'Run ' . ConsoleScript::command('audit:install-log') . ', then ' . ConsoleScript::command('migrate') . '.',
            )];
        }
        if (!$store->chained()) {
            return [];
        }
        $unkeyed = $store->keyed() ? [] : [new Finding(
            'audit.log_key',
            Severity::Warning,
            'The audit chain has no key, so someone who can write to the database can rewrite entries and their hashes unnoticed.',
            hint: 'Set audit.log.key from the environment (APP_AUDIT__LOG__KEY), and audit.log.unkeyed_until to the newest sequence written before it.',
        )];

        $report = $store->verify(1000);
        if ($report->intact) {
            return $unkeyed;
        }

        return [...$unkeyed, new Finding(
            'audit.chain',
            Severity::Error,
            "The security audit log's hash chain is broken at entry {$report->brokenAt}: {$report->problem}",
            hint: 'Entries were changed or removed outside the application. Keep the database as it is for investigation, and run ' . ConsoleScript::command('audit:verify') . '.',
        )];
    }
}
