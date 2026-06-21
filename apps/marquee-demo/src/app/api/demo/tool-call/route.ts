/**
 * POST /api/demo/tool-call
 * Step 3: Execute a mock calendar tool call through the TheAuth authorization engine.
 * The tool surface is simulated; the auth/audit is real.
 */

import { generateId } from "@glinr/theauth";
import { NextResponse } from "next/server";
import { getSessionId } from "@/lib/cookie";
import { getKavach } from "@/lib/kavach-instance";
import { getSession, setSession } from "@/lib/session-store";

// Mock calendar tool responses
const MOCK_TOOLS: Record<string, (args: Record<string, unknown>) => unknown> = {
	"calendar.list_events": (args) => ({
		events: [
			{
				id: "evt_1",
				title: "Standup",
				start: args.date ?? "2026-04-17T09:00:00Z",
				duration: 15,
			},
			{
				id: "evt_2",
				title: "Design review",
				start: args.date ?? "2026-04-17T14:00:00Z",
				duration: 60,
			},
		],
	}),
	"calendar.get_event": (args) => ({
		id: args.eventId ?? "evt_1",
		title: "Standup",
		attendees: ["alice@example.com", "bob@example.com"],
		notes: "Daily sync",
	}),
	"calendar.get_free_busy": (args) => ({
		userId: args.userId ?? "demo",
		slots: [
			{ start: "2026-04-17T11:00:00Z", end: "2026-04-17T12:00:00Z", status: "free" },
			{ start: "2026-04-17T13:00:00Z", end: "2026-04-17T14:00:00Z", status: "busy" },
		],
	}),
};

const TOOL_SEQUENCE = [
	{
		tool: "calendar.list_events",
		args: { date: "2026-04-17" },
		resource: "calendar:events",
	},
	{
		tool: "calendar.get_event",
		args: { eventId: "evt_1" },
		resource: "calendar:events",
	},
	{
		tool: "calendar.get_free_busy",
		args: { userId: "demo" },
		resource: "calendar:free_busy",
	},
];

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

		// Determine which tool to call next in sequence
		const callIndex = session.toolCalls.length;
		if (callIndex >= TOOL_SEQUENCE.length) {
			return NextResponse.json({ error: "All tool calls complete" }, { status: 400 });
		}

		const { tool, args, resource } = TOOL_SEQUENCE[callIndex] as (typeof TOOL_SEQUENCE)[number];

		const kavach = await getKavach();
		const start = Date.now();

		const authResult = await kavach.authorize(session.agentId, {
			action: "read",
			resource,
			arguments: args,
		});

		const durationMs = Date.now() - start;

		const toolOutput = authResult.allowed ? (MOCK_TOOLS[tool]?.(args) ?? null) : null;

		const callRecord = {
			tool,
			input: args,
			output: toolOutput,
			timestamp: new Date(),
			auditId: authResult.auditId,
		};

		session.toolCalls.push(callRecord);

		// Append a synthetic audit entry to the session's audit log
		session.auditLog.push({
			id: authResult.auditId || generateId(),
			agentId: session.agentId ?? "unknown",
			userId: session.userId,
			action: "read",
			resource,
			parameters: args,
			result: authResult.allowed ? "allowed" : "denied",
			reason: authResult.reason,
			durationMs,
			timestamp: new Date(),
		});

		setSession(sessionId, session);

		return NextResponse.json({
			success: authResult.allowed,
			tool,
			authResult,
			toolOutput,
			callIndex,
			totalCalls: TOOL_SEQUENCE.length,
			allComplete: session.toolCalls.length >= TOOL_SEQUENCE.length,
			apiRequest: {
				method: "POST",
				path: "/kavach/authorize",
				body: {
					agentId: session.agentId,
					action: "read",
					resource,
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
