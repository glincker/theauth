/**
 * POST /api/demo/spawn-agent
 * Step 2: Spawn an agent with read-only access to the "calendar" mock tool.
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
		if (!session || !session.passkeyRegistered) {
			return NextResponse.json({ error: "Complete step 1 first" }, { status: 400 });
		}

		const kavach = await getKavach();

		const agentName = `${session.userName}'s calendar-reader`;

		const agent = await kavach.agent.create({
			ownerId: session.userId,
			name: agentName,
			type: "autonomous",
			permissions: [
				{
					resource: "calendar:*",
					actions: ["read"],
					constraints: {
						maxCallsPerHour: 30,
					},
				},
			],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		session.agentId = agent.id;
		session.agentToken = agent.token;
		session.agentName = agentName;
		setSession(sessionId, session);

		return NextResponse.json({
			success: true,
			agentId: agent.id,
			agentName,
			permissions: agent.permissions,
			expiresAt: agent.expiresAt,
			tokenPayload: {
				agent_id: agent.id,
				owner: session.userId,
				scope: "calendar:read",
				exp: Math.floor((agent.expiresAt?.getTime() ?? Date.now() + 3600000) / 1000),
			},
			apiRequest: {
				method: "POST",
				path: "/api/demo/spawn-agent",
				body: {
					ownerId: session.userId,
					name: agentName,
					type: "autonomous",
					permissions: [{ resource: "calendar:*", actions: ["read"] }],
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
