/**
 * Policy shrink demo, in memory. Replays calls through authorize() so real decision rows are written, then
 * proposes a smaller permission set and checks it against the recorded decisions.
 */
import {
	analyzeUsage,
	createTheAuth,
	previewPolicyChange,
	suggestShrink,
	users,
} from "@glinr/theauth";

const auth = await createTheAuth({
	database: { provider: "sqlite", url: ":memory:" },
	agents: { auditAll: true },
});

const now = new Date();
await auth.db.insert(users).values({
	id: "owner-1",
	email: "owner@example.com",
	name: "Owner",
	createdAt: now,
	updatedAt: now,
});

const agent = await auth.agent.create({
	ownerId: "owner-1",
	name: "support-bot",
	type: "service",
	permissions: [
		{ resource: "mcp:github:repos", actions: ["read", "write"] },
		{ resource: "mcp:github:issues", actions: ["read", "write"] },
		{ resource: "mcp:github:pulls", actions: ["read"] },
		{ resource: "tool:db:orders", actions: ["query"] },
		{ resource: "tool:db:users", actions: ["query", "delete"] },
		{ resource: "tool:mail", actions: ["send"] },
		{ resource: "tool:billing", actions: ["*"] },
	],
});

// A deterministic call log: [action, resource, how many times].
const traffic: Array<[string, string, number]> = [
	["read", "mcp:github:repos", 212],
	["read", "mcp:github:issues", 148],
	["write", "mcp:github:issues", 37],
	["query", "tool:db:orders", 96],
	["query", "tool:db:users", 3],
	["delete", "mcp:github:repos", 2], // never granted, denied
];
for (const [action, resource, times] of traffic) {
	for (let i = 0; i < times; i++) await auth.authorize(agent.id, { action, resource });
}

const analysis = await analyzeUsage(auth.db, agent.id, {});
console.log("granted (one entry per action):", analysis.granted.length);
console.log("used:");
for (const u of analysis.used) {
	console.log(`  ${u.permission.resource} ${u.permission.actions[0]}  x${u.count}`);
}
console.log("never used:");
for (const p of analysis.unused) console.log(`  ${p.resource} ${p.actions.join(",")}`);

const plan = suggestShrink(analysis, { minObservations: 5 });
console.log("\nkeep:", JSON.stringify(plan.keep));
console.log("remove:", JSON.stringify(plan.remove));

// Proof against the recorded decisions. Review newlyDenied before applying.
const report = await previewPolicyChange(auth.db, agent.id, plan.keep, {});
console.log("\nreplayed allows:", report.replayedAllows);
console.log("still allowed:  ", report.stillAllowed);
console.log("newly denied:   ", report.newlyDeniedCount);
for (const r of report.newlyDenied.slice(0, 5)) console.log(`  ${r.action} ${r.resource}`);
console.log("newly allowed (was denied for lack of a grant):", report.wouldAlsoAllowCount);
