/**
 * GET /api/demo/state: current demo step state for the session. The UI polls this to sync.
 */

import { NextResponse } from "next/server";
import { getSessionId } from "@/lib/cookie";
import { getSession } from "@/lib/session-store";

export async function GET(): Promise<NextResponse> {
	const sessionId = await getSessionId();
	if (!sessionId) {
		return NextResponse.json({ step: 0 });
	}

	const session = getSession(sessionId);
	if (!session) {
		return NextResponse.json({ step: 0 });
	}

	return NextResponse.json({
		step: deriveStep(session),
		userId: session.userId,
		userName: session.userName,
		passkeyRegistered: session.passkeyRegistered,
		agentId: session.agentId,
		agentName: session.agentName,
		subAgentId: session.subAgentId,
		subAgentName: session.subAgentName,
		toolCallsComplete: session.toolCalls.length,
		delegationDone: session.delegationDone,
		exportReady: session.exportReady,
		auditLog: session.auditLog.map((e) => ({
			id: e.id,
			action: e.action,
			resource: e.resource,
			result: e.result,
			timestamp: e.timestamp.toISOString(),
			durationMs: e.durationMs,
		})),
	});
}

function deriveStep(session: {
	passkeyRegistered: boolean;
	agentId: string | null;
	toolCalls: unknown[];
	delegationDone: boolean;
	exportReady: boolean;
}): number {
	if (session.exportReady) return 5;
	if (session.delegationDone) return 4;
	if (session.toolCalls.length >= 3) return 3;
	if (session.agentId) return 2;
	if (session.passkeyRegistered) return 1;
	return 0;
}
