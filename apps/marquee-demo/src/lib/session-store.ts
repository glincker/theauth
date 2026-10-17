/**
 * In-memory session store keyed by the session cookie. State is per process and lost on cold start, fine for a demo.
 */

export interface DemoAuditEntry {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	parameters: Record<string, unknown>;
	result: "allowed" | "denied" | "rate_limited";
	reason?: string;
	durationMs: number;
	timestamp: Date;
}

export interface DemoSession {
	userId: string;
	userName: string;
	passkeyRegistered: boolean;
	agentId: string | null;
	agentToken: string | null;
	agentName: string | null;
	subAgentId: string | null;
	subAgentName: string | null;
	toolCalls: ToolCallRecord[];
	auditLog: DemoAuditEntry[];
	delegationDone: boolean;
	exportReady: boolean;
}

export interface ToolCallRecord {
	tool: string;
	input: Record<string, unknown>;
	output: unknown;
	timestamp: Date;
	auditId: string;
}

// Module-level so it persists across requests in one server process. Not suitable for production.
const store = new Map<string, DemoSession>();

export function getSession(id: string): DemoSession | undefined {
	return store.get(id);
}

export function setSession(id: string, session: DemoSession): void {
	store.set(id, session);
}

export function deleteSession(id: string): void {
	store.delete(id);
}

export function createFreshSession(userId: string, userName: string): DemoSession {
	return {
		userId,
		userName,
		passkeyRegistered: false,
		agentId: null,
		agentToken: null,
		agentName: null,
		subAgentId: null,
		subAgentName: null,
		toolCalls: [],
		auditLog: [],
		delegationDone: false,
		exportReady: false,
	};
}
