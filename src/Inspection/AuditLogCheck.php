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

        $report = $store->verify(1000);
        if ($report->intact) {
            return [];
        }

        return [new Finding(
            'audit.chain',
            Severity::Error,
            "The security audit log's hash chain is broken at entry {$report->brokenAt}: {$report->problem}",
            hint: 'Entries were changed or removed outside the application. Keep the database as it is for investigation, and run ' . ConsoleScript::command('audit:verify') . '.',
        )];
    }
}
