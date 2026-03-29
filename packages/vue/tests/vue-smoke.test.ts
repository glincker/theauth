import { createApp, defineComponent, nextTick } from "vue";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createKavachPlugin, useSession, useSignIn, useSignOut, useUser } from "../src/index.js";

const SESSION_KEY = "kavach_session";

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
	app.use(createKavachPlugin({ basePath: "/api/kavach" }));
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

	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (!url.endsWith("/auth/sign-in")) {
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
	app.use(createKavachPlugin({ basePath: "/api/kavach" }));
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

	app.unmount();
});
