/**
 * POST /api/demo/signup
 * Step 1: Register a user with a simulated passkey.
 *
 * In a production passkey flow, we would call navigator.credentials.create()
 * in the browser and verify the attestation here. For the demo we simulate
 * the passkey ceremony and create a real KavachOS session record so all
 * downstream steps use authentic data.
 */

import { generateId } from "kavachos";
import { NextResponse } from "next/server";
import { makeSessionCookie } from "@/lib/cookie";
import { getKavach } from "@/lib/kavach-instance";
import { createFreshSession, setSession } from "@/lib/session-store";

export async function POST(request: Request): Promise<NextResponse> {
	try {
		const body = (await request.json()) as { userName?: string };
		const userName =
			typeof body.userName === "string" && body.userName.trim()
				? body.userName.trim()
				: "Demo User";

		const sessionId = generateId();
		const userId = generateId();

		// Pre-warm the KavachOS singleton so it's ready for step 2.
		// The user lives only in the session store; no DB call needed here.
		await getKavach();

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
