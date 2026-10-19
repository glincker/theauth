export type Page =
	| "overview"
	| "agents"
	| "users"
	| "permissions"
	| "delegations"
	| "mcp-servers"
	| "devices"
	| "audit"
	| "approvals"
	| "explain"
	| "revocations"
	| "security"
	| "settings";

export type Theme = "light" | "dark";

export interface DashboardProps {
	apiUrl: string;
	theme?: Theme;
	demo?: boolean;
}
