/**
 * The React provider on the email and password preset, against the real core handler:
 * sign up, verify, sign in, session read, sign out. No mocked routes.
 */
import type { ReactNode } from "react";
import { act, useEffect } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TheAuthProvider } from "../src/context.js";
import { useEmailPassword, useSession, useSignIn, useSignOut, useSignUp } from "../src/hooks.js";

const PASSWORD = "correct horse battery";

// The bodies below are what `createTheAuthHandler` answers on the /auth/email/* routes. The
// full flow against the real handler runs in packages/client/tests/session-store-email-password.test.ts
// (jsdom replaces AbortSignal, which breaks Request cloning inside the core router).
const ADA = { id: "u1", email: "ada@example.com", name: "Ada", emailVerified: true };
let verified = false;

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

const calls: string[] = [];
const fakeServer = (async (input: RequestInfo | URL, init?: RequestInit) => {
	const path = String(input);
	calls.push(`${init?.method ?? "GET"} ${path}`);
	if (path.endsWith("/auth/email/sign-up")) return json(201, { verificationRequired: true });
	if (path.endsWith("/auth/email/verify")) {
		verified = true;
		return json(200, { verified: true, user: ADA });
	}
	if (path.endsWith("/auth/email/sign-in")) {
		if (!verified) {
			return json(403, {
				error: {
					code: "EMAIL_NOT_VERIFIED",
					message: "Verify your email address before signing in",
				},
			});
		}
		return json(200, { user: ADA, session: { token: "tok", expiresAt: "2999-01-01T00:00:00Z" } });
	}
	if (path.endsWith("/auth/session")) {
		return init?.headers && JSON.stringify(init.headers).includes("tok")
			? json(200, { user: ADA, session: { id: "s1", expiresAt: "2999-01-01T00:00:00Z" } })
			: json(401, { error: "Not authenticated" });
	}
	if (path.endsWith("/auth/sign-out")) return json(200, { success: true });
	return json(404, {});
}) as typeof fetch;

type Snapshot = {
	session: ReturnType<typeof useSession>;
	signIn: ReturnType<typeof useSignIn>;
	signUp: ReturnType<typeof useSignUp>;
	signOut: ReturnType<typeof useSignOut>;
	email: ReturnType<typeof useEmailPassword>;
};

let root: Root | null = null;
let latest: Snapshot | null = null;

function Probe() {
	const session = useSession();
	const signIn = useSignIn();
	const signUp = useSignUp();
	const signOut = useSignOut();
	const email = useEmailPassword();
	useEffect(() => {
		latest = { session, signIn, signUp, signOut, email };
	});
	return null;
}

function render(ui: ReactNode) {
	const container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
	void act(() => {
		root?.render(ui);
	});
}

async function settle() {
	for (let i = 0; i < 5; i++) {
		await act(async () => {
			await new Promise((r) => setTimeout(r, 20));
		});
	}
}

function snap(): Snapshot {
	if (!latest) throw new Error("not rendered");
	return latest;
}

afterEach(() => {
	void act(() => root?.unmount());
	root = null;
	latest = null;
});

describe("TheAuthProvider with managed.emailPassword", () => {
	it("signs up, verifies, signs in, reads the session and signs out", async () => {
		vi.stubGlobal("fetch", fakeServer);
		render(
			<TheAuthProvider managed={{ emailPassword: true }}>
				<Probe />
			</TheAuthProvider>,
		);
		await settle();
		expect(snap().session.session).toBeNull();

		let up: Awaited<ReturnType<Snapshot["signUp"]["signUp"]>> | undefined;
		await act(async () => {
			up = await snap().signUp.signUp("ada@example.com", PASSWORD, "Ada");
		});
		expect(up).toEqual({ success: true, data: { verificationRequired: true } });
		expect(snap().session.session).toBeNull();

		let early: Awaited<ReturnType<Snapshot["signIn"]["signIn"]>> | undefined;
		await act(async () => {
			early = await snap().signIn.signIn("ada@example.com", PASSWORD);
		});
		expect(early).toMatchObject({ success: false, code: "EMAIL_NOT_VERIFIED" });
		expect(snap().signIn.error).toBeTruthy();

		await act(async () => {
			expect(await snap().email.verifyEmail("token-from-email")).toEqual({
				success: true,
				data: undefined,
			});
		});

		await act(async () => {
			expect(await snap().signIn.signIn("ada@example.com", PASSWORD)).toEqual({
				success: true,
				data: undefined,
			});
		});
		await settle();
		expect(snap().session.session?.user).toMatchObject({ email: "ada@example.com" });

		await act(async () => {
			await snap().signOut.signOut();
		});
		await settle();
		expect(snap().session.session).toBeNull();
		expect(calls).toContain("POST /api/theauth/auth/email/sign-up");
		expect(calls).toContain("POST /api/theauth/auth/email/sign-in");
	});
});
