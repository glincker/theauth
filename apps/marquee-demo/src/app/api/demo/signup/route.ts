/**
 * POST /api/demo/signup (step 1). Simulates the passkey ceremony and creates a real session record.
 * Production would call navigator.credentials.create() and verify the attestation here.
 */

import { generateId } from "@glinr/theauth";
import { NextResponse } from "next/server";
import { makeSessionCookie } from "@/lib/cookie";
import { createFreshSession, setSession } from "@/lib/session-store";
import { getTheAuth } from "@/lib/theauth-instance";

export async function POST(request: Request): Promise<NextResponse> {
	try {
		const body = (await request.json()) as { userName?: string };
		const userName =
			typeof body.userName === "string" && body.userName.trim()
				? body.userName.trim()
				: "Demo User";

		const sessionId = generateId();
		const userId = generateId();

		// Pre-warm the TheAuth singleton so it's ready for step 2.
		// The user lives only in the session store; no DB call needed here.
		await getTheAuth();

		const session = createFreshSession(userId, userName);
		session.passkeyRegistered = true;

		setSession(sessionId, session);

		const res = NextResponse.json({
			success: true,
			userId,
			userName,
			simulatedPasskeyId: `pk_${sessionId.slice(0, 16)}`,
			tokenPayload: {
				sub: userId,
				name: userName,
				iat: Math.floor(Date.now() / 1000),
				auth_method: "passkey",
			},
			apiRequest: {
				method: "POST",
				path: "/api/demo/signup",
				body: { userName },
			},
		});

		res.headers.set("Set-Cookie", makeSessionCookie(sessionId));
		return res;
	} catch (err) {
		return NextResponse.json(
			{ error: err instanceof Error ? err.message : "Unknown error" },
			{ status: 500 },
		);
	}
}
