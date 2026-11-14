# Changelog

All Zana packages share one version number and are released together. A release that did
not change this package is not listed.

## 2.20.0 — 2026-11-14

### Security

- `audit.log.key` keys the hash chain: each hash is an HMAC-SHA256, which nobody who can only write to the database can
  forge (S21). Every entry after `audit.log.unkeyed_until` must be keyed, so a log rewritten in the unkeyed form fails
  `verify()` too. Without a key, the chain uses SHA-256 as before.
- `check` warns (`audit.log_key`) when the chain is on without a key, and `verify()` says when an entry predates the key.

## 2.17.0 — 2026-11-06

### Added

- The security audit log records mj-zana/security's `RoleAssigned` and `RoleRevoked`: who changed
  whose role, and where.

## 2.16.0 — 2026-11-06

### Added

- The security audit log records mj-zana/security's second-factor events: `TwoFactorEnabled`,
  `TwoFactorDisabled`, `TwoFactorFailed` (with the reason) and `RecoveryCodeUsed` (with the codes
  left).

## 2.15.0 — 2026-11-06

### Added

- A security audit log beside the content revisions (FE-58, ADR-030):
  - `AuditLog::record()` (scoped: the signed-in user, the client address and the correlation id);
  - `AuditLogStore`, which is append-only, with optional hash chaining (`audit.log.chain`);
  - `#[Audited]` and `AuditedBehavior` for mediator commands, recording only the listed fields;
  - mj-zana/security's sign-in, sign-out and password reset events, recorded with
    `audit.log.enabled`;
  - `audit:install-log`, `audit:verify`, `audit:prune` (`audit.log.retention_days`) and
    `audit:log`;
  - the `audit.log` and `audit.chain` checks, and `inspect audit-log`.
- Tested on SQLite, MySQL and PostgreSQL, including four processes appending to one chain.

### Changed

- Requires `mj-zana/core` ^2.11 and `mj-zana/database` ^2.12. Applications that only keep
  revisions are unchanged: the audit log is off until `audit.log.enabled` is true.

## 2.4.0 — 2026-10-26

### Changed

- Factory registrations declare the services they resolve with `uses()`, so the container checks
  their lifetimes at startup (FE-40).
- Requires `mj-zana/core` ^2.4.

## 2.3.0 — 2026-10-26

### Changed

- Tests and tooling (`tests/`, `phpunit.xml.dist`, `phpstan.neon.dist`) are no longer in Composer
  archives, so they stay out of production `vendor/` folders (FE-17).

## 2.2.0 — 2026-10-26

First release (FE-37). Content revisions per record and locale with author and date, history,
diffs and restore, stored in the application's database.
