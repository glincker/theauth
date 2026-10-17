// Emits the guardTool snippet matching a playground run.

import type { PlaygroundPolicy, ToolCall } from "./presets.js";

function indent(text: string, spaces: number): string {
	const pad = " ".repeat(spaces);
	return text
		.split("\n")
		.map((line, i) => (i === 0 ? line : pad + line))
		.join("\n");
}

function literal(value: string | number): string {
	return typeof value === "number" ? String(value) : JSON.stringify(value);
}

export function buildSnippet(call: ToolCall, policy: PlaygroundPolicy): string {
	const policyBlock = indent(
		JSON.stringify({ taint: policy.taint, risk: policy.risk }, null, 2),
		2,
	);
	const argLines = Object.entries(call.args).map(([name, value]) => {
		const labels = call.labels[name];
		const v =
			labels && labels.length > 0
				? `tainted(${literal(value)}, ${JSON.stringify(labels)})`
				: literal(value);
		return `  ${name}: ${v},`;
	});
	const riskLine =
		call.tool === "pay"
			? "\n    risk: (args) => ({ amount: args.amount, currency: args.currency }),"
			: "";
	const tainting = Object.keys(call.labels).length > 0;
	const imports = ["createTheAuth", "guardTool", "ToolApprovalRequiredError", "ToolDeniedError"];
	if (tainting) imports.push("tainted");
	return `import { ${imports.sort().join(", ")} } from "@glinr/theauth";

const theauth = await createTheAuth({
  database: { provider: "sqlite", url: ":memory:" },
  agents: { enabled: true, maxPerUser: 5, defaultPermissions: [], auditAll: true },
  audit: { tamperEvident: true, hmacKey: process.env.AUDIT_HMAC_KEY },
  policy: ${policyBlock},
});

// An agent that may execute this tool. The policy decides the rest.
const agent = await theauth.agent.create({
  ownerId: "user-1",
  name: "my-agent",
  type: "autonomous",
  permissions: [{ resource: "tool:${call.tool}", actions: ["execute"] }],
});

const ${call.tool} = guardTool(
  theauth,
  {
    agentId: agent.id,${riskLine}
  },
  {
    name: "${call.tool}",
    execute: async (args) => runTool(args), // your real implementation
  },
);

try {
  await ${call.tool}.execute({
${argLines.join("\n")}
  });
} catch (error) {
  if (error instanceof ToolDeniedError) console.warn("blocked:", error.code, error.reason);
  else if (error instanceof ToolApprovalRequiredError) console.warn("needs approval:", error.approvalRequestId);
  else throw error;
}
`;
}
