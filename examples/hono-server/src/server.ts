// TheAuth Hono Server Example
//
// Start: pnpm --filter @glinr/theauth-example-hono-server start
//
// Try:
//   curl http://localhost:3000/api/agents -X POST -H "Content-Type: application/json" \
//     -d '{"ownerId":"user-1","name":"my-agent","type":"autonomous","permissions":[{"resource":"mcp:*","actions":["read"]}]}'
//
//   curl http://localhost:3000/api/agents
//   curl http://localhost:3000/api/audit

import { createTheAuth, users } from "@glinr/theauth";
import { kavachHono } from "@glinr/theauth-hono";
import { serve } from "@hono/node-server";
import { sql } from "drizzle-orm";
import { Hono } from "hono";

const PORT = 3000;

// ─── Database setup ───────────────────────────────────────────────────────────

function createTables(auth: Awaited<ReturnType<typeof createTheAuth>>): void {
	auth.db.run(sql`
		CREATE TABLE IF NOT EXISTS kavach_users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			name TEXT,
			external_id TEXT,
			external_provider TEXT,
			metadata TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`);

	auth.db.run(sql`
		CREATE TABLE IF NOT EXISTS kavach_agents (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL REFERENCES kavach_users(id),
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			token_hash TEXT NOT NULL,
			token_prefix TEXT NOT NULL,
			expires_at INTEGER,
			last_active_at INTEGER,
			metadata TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`);

	auth.db.run(sql`
		CREATE TABLE IF NOT EXISTS kavach_permissions (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
			resource TEXT NOT NULL,
			actions TEXT NOT NULL,
			constraints TEXT,
			created_at INTEGER NOT NULL
		)
	`);

	auth.db.run(sql`
		CREATE TABLE IF NOT EXISTS kavach_audit_logs (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES kavach_agents(id),
			user_id TEXT NOT NULL REFERENCES kavach_users(id),
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			parameters TEXT,
			result TEXT NOT NULL,
			reason TEXT,
			duration_ms INTEGER NOT NULL,
			tokens_cost INTEGER,
			ip TEXT,
			user_agent TEXT,
			timestamp INTEGER NOT NULL
		)
	`);

	auth.db.run(sql`
		CREATE TABLE IF NOT EXISTS kavach_rate_limits (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
			resource TEXT NOT NULL,
			window_start INTEGER NOT NULL,
			count INTEGER NOT NULL DEFAULT 0
		)
	`);

	auth.db.run(sql`
		CREATE TABLE IF NOT EXISTS kavach_delegation_chains (
			id TEXT PRIMARY KEY,
			from_agent_id TEXT NOT NULL REFERENCES kavach_agents(id),
			to_agent_id TEXT NOT NULL REFERENCES kavach_agents(id),
			permissions TEXT NOT NULL,
			depth INTEGER NOT NULL DEFAULT 1,
			max_depth INTEGER NOT NULL DEFAULT 3,
			status TEXT NOT NULL DEFAULT 'active',
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)
	`);
}

function seedUser(auth: Awaited<ReturnType<typeof createTheAuth>>): void {
	auth.db
		.insert(users)
		.values({
			id: "user-1",
			email: "demo@theauth.dev",
			name: "Demo User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
}

// ─── Homepage HTML ────────────────────────────────────────────────────────────

function homepageHtml(): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TheAuth Server</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Inter, system-ui, sans-serif;
      background: #0f0f0f;
      color: #e5e5e5;
      padding: 48px 24px;
      line-height: 1.6;
    }
    .container { max-width: 760px; margin: 0 auto; }
    h1 { font-size: 1.75rem; font-weight: 700; color: #C9A84C; margin-bottom: 8px; }
    .subtitle { color: #888; margin-bottom: 40px; font-size: 0.95rem; }
    h2 { font-size: 1rem; font-weight: 600; color: #C9A84C; margin: 32px 0 12px; text-transform: uppercase; letter-spacing: 0.06em; }
    ul { list-style: none; }
    li { margin-bottom: 8px; }
    a { color: #C9A84C; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .badge {
      display: inline-block;
      padding: 1px 8px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', 'Fira Mono', monospace;
      font-size: 0.7rem;
      font-weight: 600;
      margin-right: 8px;
      vertical-align: middle;
    }
    .get  { background: #1a3a1a; color: #4ade80; }
    .post { background: #1a2e3a; color: #60a5fa; }
    .patch { background: #2a2a1a; color: #facc15; }
    .del  { background: #3a1a1a; color: #f87171; }
    code {
      font-family: 'JetBrains Mono', 'Fira Mono', monospace;
      font-size: 0.85rem;
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      border-radius: 6px;
      padding: 16px;
      display: block;
      white-space: pre;
      overflow-x: auto;
      color: #d4d4d4;
      margin-top: 8px;
    }
    .endpoint { display: flex; align-items: baseline; gap: 8px; margin-bottom: 6px; }
    .path { font-family: 'JetBrains Mono', 'Fira Mono', monospace; font-size: 0.85rem; color: #e5e5e5; }
    .desc { font-size: 0.82rem; color: #888; }
    .status { display: inline-flex; align-items: center; gap: 6px; margin-bottom: 32px; }
    .dot { width: 8px; height: 8px; background: #4ade80; border-radius: 50%; display: inline-block; }
  </style>
</head>
<body>
  <div class="container">
    <h1>TheAuth</h1>
    <p class="subtitle">Auth OS for AI agents — agent identity, permissions, delegation, audit</p>

    <div class="status">
      <span class="dot"></span>
      <span style="font-size:0.85rem;color:#4ade80">Server running on port ${PORT}</span>
    </div>

    <h2>Agent endpoints</h2>
    <ul>
      <li class="endpoint">
        <span class="badge post">POST</span>
        <span class="path"><a href="/api/agents">/api/agents</a></span>
        <span class="desc">create an agent</span>
      </li>
      <li class="endpoint">
        <span class="badge get">GET</span>
        <span class="path"><a href="/api/agents">/api/agents</a></span>
        <span class="desc">list all agents</span>
      </li>
      <li class="endpoint">
        <span class="badge get">GET</span>
        <span class="path">/api/agents/:id</span>
        <span class="desc">get an agent by id</span>
      </li>
      <li class="endpoint">
        <span class="badge patch">PATCH</span>
        <span class="path">/api/agents/:id</span>
        <span class="desc">update name, permissions, or expiry</span>
      </li>
      <li class="endpoint">
        <span class="badge del">DELETE</span>
        <span class="path">/api/agents/:id</span>
        <span class="desc">revoke an agent</span>
      </li>
      <li class="endpoint">
        <span class="badge post">POST</span>
        <span class="path">/api/agents/:id/rotate</span>
        <span class="desc">rotate bearer token</span>
      </li>
    </ul>

    <h2>Authorization</h2>
    <ul>
      <li class="endpoint">
        <span class="badge post">POST</span>
        <span class="path">/api/authorize</span>
        <span class="desc">check permission by agent id</span>
      </li>
      <li class="endpoint">
        <span class="badge post">POST</span>
        <span class="path">/api/authorize/token</span>
        <span class="desc">check permission by bearer token</span>
      </li>
    </ul>

    <h2>Delegation</h2>
    <ul>
      <li class="endpoint">
        <span class="badge post">POST</span>
        <span class="path">/api/delegations</span>
        <span class="desc">create a delegation chain</span>
      </li>
      <li class="endpoint">
        <span class="badge get">GET</span>
        <span class="path">/api/delegations/:agentId</span>
        <span class="desc">list chains for an agent</span>
      </li>
      <li class="endpoint">
        <span class="badge del">DELETE</span>
        <span class="path">/api/delegations/:id</span>
        <span class="desc">revoke a delegation</span>
      </li>
    </ul>

    <h2>Audit</h2>
    <ul>
      <li class="endpoint">
        <span class="badge get">GET</span>
        <span class="path"><a href="/api/audit">/api/audit</a></span>
        <span class="desc">query audit logs</span>
      </li>
      <li class="endpoint">
        <span class="badge get">GET</span>
        <span class="path"><a href="/api/audit/export?format=json">/api/audit/export</a></span>
        <span class="desc">export as json or csv</span>
      </li>
    </ul>

    <h2>Dashboard</h2>
    <ul>
      <li class="endpoint">
        <span class="badge get">GET</span>
        <span class="path"><a href="/api/dashboard/stats">/api/dashboard/stats</a></span>
        <span class="desc">agent and audit summary stats</span>
      </li>
      <li class="endpoint">
        <span class="badge get">GET</span>
        <span class="path"><a href="/api/dashboard/agents">/api/dashboard/agents</a></span>
        <span class="desc">agents with filter support</span>
      </li>
    </ul>

    <h2>Quick start</h2>
    <code># Create an agent for the seed user
curl http://localhost:${PORT}/api/agents -X POST \\
  -H "Content-Type: application/json" \\
  -d '{"ownerId":"user-1","name":"my-agent","type":"autonomous","permissions":[{"resource":"mcp:*","actions":["read"]}]}'

# List all agents
curl http://localhost:${PORT}/api/agents

# Check a permission by agent id (replace &lt;id&gt; with the id from above)
curl http://localhost:${PORT}/api/authorize -X POST \\
  -H "Content-Type: application/json" \\
  -d '{"agentId":"&lt;id&gt;","action":"read","resource":"mcp:github:repos"}'

# Query the audit log
curl http://localhost:${PORT}/api/audit</code>
  </div>
</body>
</html>`;
}

// ─── Server bootstrap ─────────────────────────────────────────────────────────

async function main(): Promise<void> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: "theauth.db" },
		agents: {
			enabled: true,
			maxPerUser: 50,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	createTables(auth);
	seedUser(auth);

	const api = kavachHono(auth);

	const app = new Hono();

	app.get("/", (c) => c.html(homepageHtml()));

	app.route("/api", api);

	serve({ fetch: app.fetch, port: PORT }, () => {
		process.stdout.write(`
TheAuth Hono server
  http://localhost:${PORT}

Endpoints (all prefixed /api):
  POST   /api/agents
  GET    /api/agents
  GET    /api/agents/:id
  PATCH  /api/agents/:id
  DELETE /api/agents/:id
  POST   /api/agents/:id/rotate
  POST   /api/authorize
  POST   /api/authorize/token
  POST   /api/delegations
  GET    /api/delegations/:agentId
  DELETE /api/delegations/:id
  GET    /api/audit
  GET    /api/audit/export
  GET    /api/dashboard/stats
  GET    /api/dashboard/agents
  GET    /api/dashboard/audit

Seed user: user-1  (demo@theauth.dev)
Database:  theauth.db

`);
	});
}

main().catch((err: unknown) => {
	process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`);
	process.exit(1);
});
