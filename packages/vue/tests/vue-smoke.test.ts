import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createApp, defineComponent, nextTick } from "vue";
import {
	createTheAuthPlugin,
	useSession,
	useSignIn,
	useSignOut,
	useSignUp,
	useUser,
} from "../src/index.js";

const SESSION_KEY = "theauth_session";

const restoredSession = {
	token: "session-token-1",
	user: {
		id: "user-1",
		email: "ada@example.com",
		name: "Ada",
	},
	expiresAt: "2026-03-30T00:00:00.000Z",
};

function flush(): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, 0));
}

function installMockLocalStorage() {
	const store = new Map<string, string>();
	const mockStorage = {
		getItem(key: string) {
			return store.get(key) ?? null;
		},
		setItem(key: string, value: string) {
			store.set(key, value);
		},
		removeItem(key: string) {
			store.delete(key);
		},
		clear() {
			store.clear();
		},
	};

	Object.defineProperty(window, "localStorage", {
		value: mockStorage,
		configurable: true,
	});
	Object.defineProperty(globalThis, "localStorage", {
		value: mockStorage,
		configurable: true,
	});
}

beforeEach(() => {
	installMockLocalStorage();
	window.localStorage.clear();
	document.body.innerHTML = "";
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => ({
			ok: true,
			status: 200,
			json: async () => ({}),
		})) as typeof fetch,
	);
});

afterEach(() => {
	vi.unstubAllGlobals();
	document.body.innerHTML = "";
	window.localStorage.clear();
});

test("restores session from localStorage when the plugin installs", async () => {
	window.localStorage.setItem(SESSION_KEY, JSON.stringify(restoredSession));

	const api: {
		session: ReturnType<typeof useSession> | null;
		user: ReturnType<typeof useUser> | null;
	} = { session: null, user: null };
	const Harness = defineComponent({
		setup() {
			api.session = useSession();
			api.user = useUser();
			return () => null;
		},
	});

	const app = createApp(Harness);
	app.use(createTheAuthPlugin({ basePath: "/api/theauth" }));
	app.mount(document.createElement("div"));

	await flush();
	await nextTick();

	expect(api.session?.session?.token).toBe(restoredSession.token);
	expect(api.user?.user?.id).toBe(restoredSession.user.id);
	expect(api.user?.isAuthenticated).toBe(true);
	expect(api.session?.isLoading).toBe(false);

	app.unmount();
});

test("sign in updates state and writes the session to localStorage", async () => {
	const signInResponse = {
		user: {
			id: "user-2",
			email: "sam@example.com",
			name: "Sam",
		},
		session: {
			token: "session-token-2",
			expiresAt: "2026-04-01T00:00:00.000Z",
		},
	};

	const signOutCalls: string[] = [];
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (url.endsWith("/auth/sign-out")) {
				signOutCalls.push(String(new Headers(init?.headers).get("authorization")));
				return { ok: true, status: 200, json: async () => ({ success: true }) };
			}
			if (!url.endsWith("/auth/username/sign-in")) {
				throw new Error(`unexpected request: ${url}`);
			}
			expect(init?.method).toBe("POST");
			expect(init?.headers).toMatchObject({ "Content-Type": "application/json" });

			return {
				ok: true,
				status: 200,
				json: async () => signInResponse,
			};
		}) as typeof fetch,
	);

	const api: {
		session: ReturnType<typeof useSession> | null;
		user: ReturnType<typeof useUser> | null;
		signIn: ReturnType<typeof useSignIn> | null;
		signOut: ReturnType<typeof useSignOut> | null;
	} = {
		session: null as ReturnType<typeof useSession> | null,
		user: null as ReturnType<typeof useUser> | null,
		signIn: null as ReturnType<typeof useSignIn> | null,
		signOut: null as ReturnType<typeof useSignOut> | null,
	};

	const Harness = defineComponent({
		setup() {
			api.session = useSession();
			api.user = useUser();
			api.signIn = useSignIn();
			api.signOut = useSignOut();
			return () => null;
		},
	});

	const app = createApp(Harness);
	app.use(createTheAuthPlugin({ basePath: "/api/theauth" }));
	app.mount(document.createElement("div"));

	await flush();
	await nextTick();

	const result = await api.signIn!.signIn("sam@example.com", "secret");
	expect(result).toEqual({ success: true, data: undefined });

	await flush();
	await nextTick();

	expect(api.user?.user?.id).toBe(signInResponse.user.id);
	expect(api.user?.isAuthenticated).toBe(true);
	expect(api.session?.session?.token).toBe(signInResponse.session.token);
	expect(JSON.parse(window.localStorage.getItem(SESSION_KEY) ?? "{}")).toMatchObject({
		token: signInResponse.session.token,
		user: signInResponse.user,
	});

	await api.signOut!.signOut();
	await flush();
	await nextTick();

	expect(api.user?.user).toBeNull();
	expect(api.user?.isAuthenticated).toBe(false);
	expect(window.localStorage.getItem(SESSION_KEY)).toBeNull();
	expect(signOutCalls).toEqual(["Bearer session-token-2"]);

	app.unmount();
});

function mountWith(options: Parameters<typeof createTheAuthPlugin>[0]) {
	const api: { session: ReturnType<typeof useSession> | null } = { session: null };
	const Harness = defineComponent({
		setup() {
			api.session = useSession();
			return () => null;
		},
	});
	const app = createApp(Harness);
	app.use(createTheAuthPlugin(options));
	app.mount(document.createElement("div"));
	return { app, api };
}

test("reads the session from the server when localStorage is empty", async () => {
	const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
		expect(String(input)).toBe("/api/theauth/auth/session");
		return {
			ok: true,
			status: 200,
			json: async () => ({
				user: { id: "user-9", username: "kay" },
				session: { id: "s", expiresAt: "2999-01-01T00:00:00.000Z" },
			}),
		};
	});
	vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
	const { app, api } = mountWith({});
	await flush();
	await nextTick();
	expect(fetchMock).toHaveBeenCalledTimes(1);
	expect(api.session?.session?.user.id).toBe("user-9");
	expect(api.session?.isLoading).toBe(false);
	app.unmount();
});

test("initialSession hydrates without a request", async () => {
	const fetchMock = vi.fn();
	vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
	const { app, api } = mountWith({ initialSession: { user: { id: "ssr-1" } } });
	await nextTick();
	expect(api.session?.session?.user.id).toBe("ssr-1");
	expect(api.session?.isLoading).toBe(false);
	expect(fetchMock).not.toHaveBeenCalled();
	app.unmount();
});

test("refetches on window focus and stops after unmount", async () => {
	const fetchMock = vi.fn(async () => ({
		ok: true,
		status: 200,
		json: async () => ({ user: { id: "u" } }),
	}));
	vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
	const { app } = mountWith({ initialSession: { user: { id: "u" } }, refetch: { onFocus: true } });
	window.dispatchEvent(new Event("focus"));
	await flush();
	expect(fetchMock).toHaveBeenCalledTimes(1);
	app.unmount();
	window.dispatchEvent(new Event("focus"));
	await flush();
	expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("emailPassword preset targets the email routes and reports verificationRequired", async () => {
	const urls: string[] = [];
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			urls.push(url);
			if (url.endsWith("/auth/email/sign-up")) {
				return { ok: true, status: 201, json: async () => ({ verificationRequired: true }) };
			}
			if (url.endsWith("/auth/email/sign-in")) {
				return {
					ok: false,
					status: 403,
					json: async () => ({ error: { code: "EMAIL_NOT_VERIFIED", message: "Verify first" } }),
				};
			}
			return { ok: false, status: 401, json: async () => ({}) };
		}) as typeof fetch,
	);
	const api: { up: ReturnType<typeof useSignUp> | null; inn: ReturnType<typeof useSignIn> | null } =
		{
			up: null,
			inn: null,
		};
	const Harness = defineComponent({
		setup() {
			api.up = useSignUp();
			api.inn = useSignIn();
			return () => null;
		},
	});
	const app = createApp(Harness);
	app.use(createTheAuthPlugin({ basePath: "/api/theauth", emailPassword: true }));
	app.mount(document.createElement("div"));
	await flush();

	expect(await api.up?.signUp("ada@example.com", "pw-long-enough")).toEqual({
		success: true,
		data: { verificationRequired: true },
	});
	expect(await api.inn?.signIn("ada@example.com", "pw-long-enough")).toEqual({
		success: false,
		error: "Verify first",
		code: "EMAIL_NOT_VERIFIED",
	});
	expect(urls).toContain("/api/theauth/auth/email/sign-up");
	expect(urls).toContain("/api/theauth/auth/email/sign-in");
	app.unmount();
});
