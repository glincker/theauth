/**
 * POST /api/demo/delegate
 * Step 4: Delegate from the parent agent to a sub-agent with narrower scope.
 */

import { NextResponse } from "next/server";
import { getSessionId } from "@/lib/cookie";
import { getKavach } from "@/lib/kavach-instance";
import { getSession, setSession } from "@/lib/session-store";

export async function POST(): Promise<NextResponse> {
	try {
		const sessionId = await getSessionId();
		if (!sessionId) {
			return NextResponse.json({ error: "No session cookie" }, { status: 401 });
		}

		const session = getSession(sessionId);
		if (!session?.agentId) {
			return NextResponse.json({ error: "Complete step 2 first" }, { status: 400 });
		}
		if (session.toolCalls.length < 3) {
			return NextResponse.json({ error: "Complete step 3 first" }, { status: 400 });
		}

		const kavach = await getKavach();

		const subAgentName = `${session.userName}'s standup-reader (delegated)`;

		// Create sub-agent with narrower scope: only list_events on one day
		const subAgent = await kavach.agent.create({
			ownerId: session.userId,
			name: subAgentName,
			type: "delegated",
			permissions: [
				{
					resource: "calendar:events",
					actions: ["read"],
					constraints: {
						maxCallsPerHour: 5,
					},
				},
			],
			expiresAt: new Date(Date.now() + 30 * 60 * 1000),
		});

		// Create the delegation chain, sub-agent's permissions are a subset
		const chain = await kavach.delegate({
			fromAgent: session.agentId,
			toAgent: subAgent.id,
			permissions: [
				{
					resource: "calendar:events",
					actions: ["read"],
					constraints: { maxCallsPerHour: 5 },
				},
			],
			expiresAt: new Date(Date.now() + 30 * 60 * 1000),
			maxDepth: 1,
		});

		session.subAgentId = subAgent.id;
		session.subAgentName = subAgentName;
		session.delegationDone = true;
		setSession(sessionId, session);

		return NextResponse.json({
			success: true,
			parentAgentId: session.agentId,
			subAgentId: subAgent.id,
			subAgentName,
			delegationChain: {
				id: chain.id,
				depth: chain.depth,
				permissions: chain.permissions,
				expiresAt: chain.expiresAt,
			},
			tokenPayload: {
				agent_id: subAgent.id,
				delegated_from: session.agentId,
				scope: "calendar:events:read",
				max_depth: 1,
			},
			apiRequest: {
				method: "POST",
				path: "/kavach/delegate",
				body: {
					fromAgent: session.agentId,
					toAgent: subAgent.id,
					permissions: [{ resource: "calendar:events", actions: ["read"] }],
				},
			},
		});
	} catch (err) {
		return NextResponse.json(
			{ error: err instanceof Error ? err.message : "Unknown error" },
			{ status: 500 },
		);
	}
}
