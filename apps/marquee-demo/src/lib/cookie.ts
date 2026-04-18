/**
 * Minimal cookie helpers for the demo session.
 */

import { cookies } from "next/headers";

const SESSION_COOKIE = "kdemo_sid";

export async function getSessionId(): Promise<string | undefined> {
	const jar = await cookies();
	return jar.get(SESSION_COOKIE)?.value;
}

export function makeSessionCookie(id: string): string {
	return `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`;
}

export function clearSessionCookie(): string {
	return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export { SESSION_COOKIE };
