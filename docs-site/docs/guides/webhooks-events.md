---
title: Webhooks and Events
description: Push HMAC-signed HTTP POST payloads to external URLs on auth events via createWebhookModule. Subscribe each endpoint to specific event types or all events.
---

# Webhooks and Events

Webhooks push signed HTTP POST requests to a URL you control whenever a TheAuth auth event occurs. Use them to sync user records, trigger onboarding flows, alert on suspicious logins, or feed events into your analytics pipeline.

## Setup

```typescript
import { createKavach, createWebhookModule } from '@glinr/theauth';

const kavach = await createKavach({
  database: { provider: 'sqlite', url: 'kavach.db' },
  plugins: [
    createWebhookModule({
      secret: process.env.KAVACH_WEBHOOK_SECRET,
      endpoints: [
        {
          url: 'https://myapp.com/webhooks/kavach',
          events: ['user.created', 'auth.login', 'agent.created'],
        },
      ],
    }),
  ],
});
```

!!! warning
    Store the webhook secret in an environment variable, not in source code. TheAuth uses it to sign every request with HMAC-SHA256.

## Subscribing to events

Each endpoint subscribes to one or more event types. Use `'*'` to receive all events.

```typescript
createWebhookModule({
  secret: process.env.KAVACH_WEBHOOK_SECRET,
  endpoints: [
    {
      url: 'https://myapp.com/webhooks/all',
      events: ['*'],
    },
    {
      url: 'https://myapp.com/webhooks/agents',
      events: ['agent.created', 'agent.revoked'],
    },
  ],
});
```

## Common events

| Event | Fired when |
|---|---|
| `user.created` | A new user account is created |
| `user.deleted` | A user account is deleted |
| `auth.login` | A user signs in |
| `auth.logout` | A user signs out |
| `agent.created` | A new agent is created |
| `agent.revoked` | An agent is revoked |
| `delegation.created` | A delegation chain is created |
| `delegation.revoked` | A delegation chain is revoked |
| `audit.anomaly` | An anomaly is detected in the audit log |

## Request headers

| Header | Value |
|---|---|
| `X-Kavach-Signature` | `sha256=<HMAC-SHA256 of raw body>` |
| `X-Kavach-Event` | Event type, e.g. `user.created` |
| `X-Kavach-Delivery` | Unique UUID for this delivery attempt |
| `X-Kavach-Timestamp` | Unix timestamp (seconds) of delivery |

## Verifying signatures

Always verify the signature before trusting the payload.

=== "Node.js"
    ```typescript
    import { createHmac, timingSafeEqual } from 'node:crypto';

    function verifyWebhook(rawBody: Buffer, signature: string, secret: string): boolean {
      const expected = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');
      return timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
    }

    // Express handler
    app.post('/webhooks/kavach', express.raw({ type: 'application/json' }), (req, res) => {
      const sig = req.headers['x-kavach-signature'] as string;
      if (!verifyWebhook(req.body, sig, process.env.KAVACH_WEBHOOK_SECRET!)) {
        return res.status(401).send('Invalid signature');
      }
      const event = JSON.parse(req.body.toString());
      // handle event...
      res.sendStatus(200);
    });
    ```
=== "Edge (Web Crypto)"
    ```typescript
    async function verifyWebhook(rawBody: string, signature: string, secret: string): Promise<boolean> {
      const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      );
      const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rawBody));
      const expected = 'sha256=' + Array.from(new Uint8Array(mac))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      return expected === signature;
    }
    ```

## Retry behavior

If your endpoint returns a non-2xx status or times out, TheAuth retries the delivery three times with exponential backoff:

| Attempt | Delay |
|---|---|
| 1 | 30 seconds |
| 2 | 5 minutes |
| 3 | 30 minutes |

After three failures the delivery is marked `failed` and no further retries occur.

## Testing a webhook URL

```typescript
await kavach.webhooks.test('https://myapp.com/webhooks/kavach');
```

The test delivery sends `{ event: 'ping', timestamp: '...' }` and respects the same signing and retry logic as real events.

!!! info "SIEM audit streaming"
    For streaming audit events to SIEM platforms (Splunk, Datadog, OpenTelemetry collectors), see the telemetry plugin. A dedicated `@glinr/audit-otlp` package for OTLP export is planned.

## Related pages

- [Audit Events](../reference/audit-events.md)
- [Configuration](../reference/configuration.md)
