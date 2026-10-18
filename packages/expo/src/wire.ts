/**
 * Wire parsing for the routes the theAuth handler serves: `POST /auth/username/sign-in`,
 * `POST /auth/username/sign-up`, `GET /auth/session` and `POST /auth/sign-out`. The
 * sign-in routes answer `{ user, session: { token, expiresAt } }`. `GET /auth/session`
 * answers `{ user, session: { id, expiresAt } }` with no token, so the caller keeps the
 * token it already holds. The older `{ data: { token, user } }` envelope is still read.
 */
import type { TheAuthSession, TheAuthUser } from "./types.js";

interface WireBody {
	data?: { token?: unknown; user?: unknown; expiresAt?: unknown };
	user?: unknown;
	session?: { token?: unknown; expiresAt?: unknown } | null;
	token?: unknown;
	error?: unknown;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function toUser(raw: unknown): TheAuthUser | null {
	if (!raw || typeof raw !== "object") return null;
	const r = raw as Record<string, unknown>;
	const id = str(r.id);
	if (!id) return null;
	const username = str(r.username);
	const email = str(r.email) ?? (username?.includes("@") ? username : undefined);
	return { id, email, name: str(r.name), image: str(r.image) } as TheAuthUser;
}

/** Reads a session from a response body. `fallbackToken` fills the token when the body has none. */
export function parseSession(body: unknown, fallbackToken?: string): TheAuthSession | null {
	if (!body || typeof body !== "object") return null;
	const b = body as WireBody;
	const user = toUser(b.data?.user ?? b.user);
	if (!user) return null;
	const token = str(b.data?.token) ?? str(b.session?.token) ?? str(b.token) ?? fallbackToken;
	if (!token) return null;
	return {
		token,
		user,
		expiresAt: str(b.data?.expiresAt) ?? str(b.session?.expiresAt),
	};
}

/** Reads an error message from `{ error: "..." }` or `{ error: { message } }`. */
export function parseError(body: unknown, fallback: string): string {
	const e = (body as WireBody | null)?.error;
	if (typeof e === "string" && e) return e;
	if (e && typeof e === "object") {
		const m = (e as { message?: unknown }).message;
		if (typeof m === "string" && m) return m;
	}
	return fallback;
}
