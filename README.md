# mj-zana/audit

Content revisions and a security audit log for Zana applications.

- **Revisions:** every published version of a record, per locale, with its
  author, its date, a history and restore.
- **Security audit log (2.15):** an append-only record of sensitive actions,
  such as sign-ins, refunds and payout account changes, for disputes and the
  data-protection rules. Hash chaining is optional.

```
composer require mj-zana/audit
```

## Revisions

Register `AuditServiceProvider` and create the table in a migration:

```php
DatabaseRevisionStore::createTable($connection);
```

```php
$revisions->record('post', $post->id, 'fr', ['title' => $title, 'body' => $body]);

foreach ($revisions->history('post', $post->id, 'fr') as $revision) {
    // $revision->version, ->author, ->createdAt, ->diff($previous)
}

$data = $revisions->restore('post', $post->id, 'fr', 3);   // then save it to the post
```

- **Locales:** versions are numbered per record and locale.
- **No duplicates:** recording identical content again does nothing.
- **Author:** the signed-in user with `mj-zana/security`. You can also pass
  one explicitly.
- **Restore:** restoring records the old content as the newest version, with
  the note "Restored version N", so the history stays complete.
- **Storage:** `DatabaseRevisionStore` (table `audit.table`), or your own
  `RevisionStoreInterface`.

## Security audit log (2.15)

Enable it, then create its tables:

```php
// config/audit.php
return [
    'log' => [
        'enabled' => true,          // record security events; check the table
        'chain' => true,            // hash chaining (off by default)
        'retention_days' => null,   // keep entries forever; or, e.g., 3650
    ],
];
```

```
php bin/zana audit:install-log
php bin/zana migrate
```

Record an action with `AuditLog`. It's scoped, so the actor is the signed-in
user, the client address is the request's, and the correlation id is the
request's, command's or job's:

```php
$audit->record('payout.account_changed', subject: "organizer:{$id}", details: ['bank' => 'Rawbank']);
```

Or mark a mediator command, and add `AuditedBehavior` to `mediator.behaviors`.
The command is recorded once its handler returns, with only the listed
fields:

```php
#[Audited('order.refund', subject: 'orderId', details: ['orderId', 'amount'])]
final readonly class RefundOrder { /* ... */ }
```

- **Security events:** with `mj-zana/security` and `mj-zana/events`, sign-ins,
  failed sign-ins (with the login typed, never the password), sign-outs and
  password resets are recorded.
- **Append-only:** the API has no update and no delete. You can also deny
  the database user `UPDATE` and `DELETE` on `audit_log`.
- **Chain:** each entry stores the hash of the previous one. `audit:verify`
  finds an edited, inserted or removed entry, and `check` verifies the newest
  1,000.
- **Retention:** `audit:prune` deletes entries older than
  `audit.log.retention_days`. Without that setting, entries are kept
  forever.
- **Reading:** `audit:log --action=security.sign_in_failed --limit=20`, and
  `inspect audit-log`.
- **No secrets:** entries cannot be changed, so record only what a dispute
  needs.

## License

MIT
