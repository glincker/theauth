// Minimal SCIM 2.0 server wired the way Okta expects. Start: pnpm --filter @glinr/theauth-example-scim-okta start

import { createTheAuth } from "@glinr/theauth";
import { scim } from "@glinr/theauth/auth";
import { theAuthHono } from "@glinr/theauth-hono";
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const PORT = Number(process.env.PORT ?? 3000);
const SCIM_TOKEN = process.env.SCIM_TOKEN;
if (!SCIM_TOKEN) throw new Error("SCIM_TOKEN env var required");

// Service agent id for provisioning writes, so every write lands in auditLogs under one actor. Seed it before boot.
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
app.route("/", theAuthHono(theauth, { allowUnauthenticated: true }));

app.get("/", (c) => c.text("theAuth SCIM server ready. hit /scim/v2/ServiceProviderConfig"));

serve({ fetch: app.fetch, port: PORT });
console.log(`SCIM server on :${PORT}, bearer token length ${SCIM_TOKEN.length}`);
