/**
 * POST /api/demo/reset
 * Clear the current browser's demo session so it can restart from step 1.
 */

import { NextResponse } from "next/server";
import { clearSessionCookie, getSessionId } from "@/lib/cookie";
import { deleteSession } from "@/lib/session-store";

export async function POST(): Promise<NextResponse> {
	const sessionId = await getSessionId();
	if (sessionId) {
		deleteSession(sessionId);
	}

	const res = NextResponse.json({ success: true });
	res.headers.set("Set-Cookie", clearSessionCookie());
	return res;
}
