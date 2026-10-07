// Minimal SCIM 2.0 server wired up the way Okta expects it.
//
// Start:   pnpm --filter @glinr/theauth-example-scim-okta start
// Verify:  curl -H "Authorization: Bearer $SCIM_TOKEN" http://localhost:3000/scim/v2/ServiceProviderConfig

import { createTheAuth } from "@glinr/theauth";
import { scim } from "@glinr/theauth/auth";
import { theAuthHono } from "@glinr/theauth-hono";
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const PORT = Number(process.env.PORT ?? 3000);
const SCIM_TOKEN = process.env.SCIM_TOKEN;
if (!SCIM_TOKEN) throw new Error("SCIM_TOKEN env var required");

// Pre-created service agent id. Create one in your app before booting and
// pass the id here so every provisioning write lands in auditLogs under a
// consistent actor. See the README for a one-liner to seed it.
const AUDIT_AGENT_ID = process.env.SCIM_AGENT_ID ?? "agent-scim-provisioner";

const theauth = await createTheAuth({
	database: { provider: "sqlite", url: process.env.DB_URL ?? "theauth.db" },
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
app.route("/", theAuthHono(theauth));

app.get("/", (c) => c.text("theAuth SCIM server ready. hit /scim/v2/ServiceProviderConfig"));

serve({ fetch: app.fetch, port: PORT });
console.log(`SCIM server on :${PORT}, bearer token length ${SCIM_TOKEN.length}`);
