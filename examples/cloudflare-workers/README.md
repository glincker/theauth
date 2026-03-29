# Cloudflare Workers example

KavachOS running on Cloudflare Workers with D1 as the database. Zero cold start, global edge deployment.

## Run

```bash
pnpm install
pnpm dev
# Uses wrangler for local development
```

## Deploy

```bash
pnpm deploy
```

## Notes

- Uses D1 binding instead of a connection URL
- Tables are auto-created on first request
- See `wrangler.toml` for D1 database configuration
