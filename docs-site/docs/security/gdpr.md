---
title: GDPR
description: Data export, account deletion, and audit log anonymization to meet GDPR requirements.
---

# GDPR

TheAuth includes built-in tools for the three GDPR obligations that most commonly require custom code: giving users their data, deleting their account on request, and anonymizing audit trails.

!!! info
    These tools cover the technical layer. Your privacy policy, data processing agreements, and response timelines are your responsibility.

## Setup

```typescript
import { createKavach } from '@glinr/theauth';
import { gdpr } from '@glinr/theauth/auth';

const kavach = await createKavach({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  baseUrl: 'https://auth.example.com',
  plugins: [
    gdpr({
      requireDeletionConfirmation: true,
    }),
  ],
});
```

## Export user data

`POST /auth/gdpr/export`

Returns a JSON bundle of all data TheAuth holds for the authenticated user: profile, sessions, audit events, and any plugin-specific records.

```typescript
const res = await fetch('/auth/gdpr/export', {
  method: 'POST',
  credentials: 'include',
});

const { data } = await res.json();
// data.user, data.sessions, data.auditLog, data.agents, ...
```

The export runs synchronously for small datasets. For accounts with large audit logs, the response includes a `downloadUrl` that expires after 24 hours instead of embedding the full payload.

## Delete account

`POST /auth/gdpr/delete`

Permanently deletes the user account and all associated data. Sessions are revoked immediately. If `requireDeletionConfirmation` is `true`, the user must provide their password:

```typescript
const res = await fetch('/auth/gdpr/delete', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    confirmation: 'DELETE', // literal string
    password: 'correct horse battery', // if requireDeletionConfirmation is true
  }),
});
```

!!! warning
    Deletion is irreversible. Any app data you store outside TheAuth that references the user ID will become orphaned. Use the `onBeforeDelete` hook to cascade deletes in your own tables first.

### onBeforeDelete hook

```typescript
gdpr({
  onBeforeDelete: async (userId) => {
    await db.delete(posts).where(eq(posts.authorId, userId));
    await db.delete(comments).where(eq(comments.userId, userId));
  },
}),
```

## Anonymize audit log

For cases where you need to retain audit records for compliance but cannot keep personal data, TheAuth can anonymize the audit log for a user without deleting it:

```typescript
import { anonymizeAuditLog } from '@glinr/theauth/modules/gdpr';

await anonymizeAuditLog(kavach, {
  userId: 'usr_abc123',
  replacement: '[deleted]', // replaces email, name, IP in log entries
});
```

The audit events remain in place with timestamps and action types intact. Personal identifiers are overwritten with the replacement string.

## Configuration reference

| Option | Type | Default | Description |
|---|---|---|---|
| `requireDeletionConfirmation` | `boolean` | `true` | Require the user's password before processing a deletion request. |
| `onBeforeDelete` | `function` | undefined | Async callback invoked before the user record is deleted. Use this to clean up app-level data. |
| `exportFormat` | `'json' \| 'url'` | `'json'` | Format for the data export response. `'json'` returns inline data, `'url'` returns a signed download URL. |

## Related pages

- [Compliance Overview](compliance.md)
- [Audit Events](../reference/audit-events.md)
- [Configuration](../reference/configuration.md)
