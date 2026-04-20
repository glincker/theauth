// Example MCP tool definitions. Replace with the tools your server
// actually wants to expose to AI agents. Each tool's name becomes the
// last segment of the permission resource, for example `mcp:file:read`
// maps to the `file:read` tool here.

export interface Tool {
	name: string;
	description: string;
	inputSchema: Record<string, unknown>;
}

export const MCP_TOOLS: Tool[] = [
	{
		name: "list_files",
		description: "List files in a directory",
		inputSchema: {
			type: "object",
			properties: {
				path: { type: "string", description: "Directory path" },
			},
			required: ["path"],
		},
	},
	{
		name: "read_file",
		description: "Read the contents of a file",
		inputSchema: {
			type: "object",
			properties: {
				path: { type: "string", description: "File path" },
			},
			required: ["path"],
		},
	},
];
