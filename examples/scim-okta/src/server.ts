// Minimal SCIM 2.0 server wired up the way Okta expects it.
//
// Start:   pnpm --filter @kavachos/example-scim-okta start
// Verify:  curl -H "Authorization: Bearer $SCIM_TOKEN" http://localhost:3000/scim/v2/ServiceProviderConfig

import { serve } from "@hono/node-server";
import { kavachHono } from "@kavachos/hono";
import { Hono } from "hono";
import { createKavach, scim } from "kavachos";

const PORT = Number(process.env.PORT ?? 3000);
const SCIM_TOKEN = process.env.SCIM_TOKEN;
if (!SCIM_TOKEN) throw new Error("SCIM_TOKEN env var required");

// Pre-created service agent id. Create one in your app before booting and
// pass the id here so every provisioning write lands in auditLogs under a
// consistent actor. See the README for a one-liner to seed it.
const AUDIT_AGENT_ID = process.env.SCIM_AGENT_ID ?? "agent-scim-provisioner";

const kavach = await createKavach({
	database: { provider: "sqlite", url: process.env.DB_URL ?? "kavach.db" },
	plugins: [
		scim({
			bearerToken: SCIM_TOKEN,
			autoCreateUsers: true,
			autoDeactivateUsers: true,
			audit: { agentId: AUDIT_AGENT_ID },
			onProvision: async (user) => {
				console.log("[scim] provisioned", user.userName);
			},
			onDeprovision: async (id) => {
				console.log("[scim] deprovisioned", id);
			},
		}),
	],
});

const app = new Hono();
app.route("/", kavachHono(kavach));

app.get("/", (c) => c.text("kavachos SCIM server ready. hit /scim/v2/ServiceProviderConfig"));

serve({ fetch: app.fetch, port: PORT });
console.log(`SCIM server on :${PORT} — bearer token length ${SCIM_TOKEN.length}`);
