# mj-zana/audit

Content revisions for Zana applications: every published version of a
record, per locale, with its author, its date, a history and restore.

```
composer require mj-zana/audit
```

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

## License

MIT
