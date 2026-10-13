import type { ExtensionAuthErrorCode } from "./errors.js";
import { ExtensionAuthError } from "./errors.js";
import { webExtensionGlobal } from "./platform.js";
import type {
	ExtensionAuth,
	ExtensionSession,
	MessageSenderLike,
	RuntimeLike,
	SignOutResult,
} from "./types.js";

const CHANNEL = "theauth:extension";
const VERSION = 1;

type Method = "getAccessToken" | "getSession" | "signIn" | "signOut";
const METHODS: readonly Method[] = ["getAccessToken", "getSession", "signIn", "signOut"];
/** Methods a content script may call. Everything else needs an extension page. */
const CONTENT_SCRIPT_METHODS: readonly Method[] = ["getAccessToken", "getSession"];

interface AuthRequest {
	channel: typeof CHANNEL;
	v: typeof VERSION;
	method: Method;
}

type AuthResponse =
	| { channel: typeof CHANNEL; ok: true; data: unknown }
	| {
			channel: typeof CHANNEL;
			ok: false;
			error: { code: ExtensionAuthErrorCode; message: string };
	  };

function isRequest(value: unknown): value is AuthRequest {
	if (typeof value !== "object" || value === null) return false;
	const o = value as Record<string, unknown>;
	return (
		o.channel === CHANNEL &&
		o.v === VERSION &&
		typeof o.method === "string" &&
		(METHODS as readonly string[]).includes(o.method)
	);
}

export interface ExposeAuthOptions {
	runtime?: RuntimeLike;
	/**
	 * Other extension ids allowed to call in through `runtime.onMessageExternal`.
	 * Empty (the default) means external senders are rejected and the external
	 * listener is not registered at all.
	 */
	allowedExtensionIds?: string[];
	/** Extra check after the built in sender validation. Return false to reject. */
	senderFilter?: (sender: MessageSenderLike, method: string) => boolean;
}

function requireRuntime(runtime: RuntimeLike | undefined): RuntimeLike {
	const resolved = runtime ?? webExtensionGlobal()?.runtime;
	if (!resolved) throw new ExtensionAuthError("invalid_config", "No runtime API: pass `runtime`");
	return resolved;
}

function isExtensionPage(runtime: RuntimeLike, sender: MessageSenderLike): boolean {
	const base = runtime.getURL?.("");
	return typeof sender.url === "string" && typeof base === "string" && sender.url.startsWith(base);
}

/**
 * Answer auth requests from popups, options pages and content scripts.
 * Only access tokens, session metadata and sign in/out results cross the
 * boundary. The refresh token never leaves the background. Returns a function
 * that removes the listeners.
 */
export function exposeAuthToBackground(
	auth: ExtensionAuth,
	options: ExposeAuthOptions = {},
): () => void {
	const runtime = requireRuntime(options.runtime);
	const allowedExternal = new Set(options.allowedExtensionIds ?? []);

	function reply(response: AuthResponse, sendResponse: (r: unknown) => void): void {
		sendResponse(response);
	}

	function fail(code: ExtensionAuthErrorCode, message: string): AuthResponse {
		return { channel: CHANNEL, ok: false, error: { code, message } };
	}

	async function dispatch(method: Method): Promise<AuthResponse> {
		try {
			let data: string | ExtensionSession | SignOutResult | null;
			if (method === "getAccessToken") data = await auth.getAccessToken();
			else if (method === "getSession") data = await auth.getSession();
			else if (method === "signIn") data = await auth.signIn();
			else data = await auth.signOut();
			return { channel: CHANNEL, ok: true, data };
		} catch (e) {
			if (e instanceof ExtensionAuthError) return fail(e.code, e.message);
			return fail("refresh_failed", "Unexpected error in the background worker");
		}
	}

	function allowed(sender: MessageSenderLike, external: boolean): "page" | "script" | null {
		if (external) {
			return sender.id !== undefined && allowedExternal.has(sender.id) ? "script" : null;
		}
		if (sender.id === undefined || sender.id !== runtime.id) return null;
		return isExtensionPage(runtime, sender) ? "page" : "script";
	}

	function makeListener(external: boolean) {
		return (
			message: unknown,
			sender: MessageSenderLike,
			sendResponse: (response: unknown) => void,
		): boolean | undefined => {
			if (!isRequest(message)) return undefined;
			const level = allowed(sender, external);
			if (level === null) {
				reply(fail("message_rejected", "Sender is not allowed"), sendResponse);
				return undefined;
			}
			const permitted =
				level === "page" || (CONTENT_SCRIPT_METHODS as readonly string[]).includes(message.method);
			if (!permitted || (options.senderFilter && !options.senderFilter(sender, message.method))) {
				reply(fail("message_rejected", "Method is not allowed for this sender"), sendResponse);
				return undefined;
			}
			void dispatch(message.method).then((r) => reply(r, sendResponse));
			return true;
		};
	}

	const internal = makeListener(false);
	runtime.onMessage.addListener(internal);
	const external = allowedExternal.size > 0 ? makeListener(true) : undefined;
	if (external) runtime.onMessageExternal?.addListener(external);

	return () => {
		runtime.onMessage.removeListener(internal);
		if (external) runtime.onMessageExternal?.removeListener(external);
	};
}

export interface AuthClientOptions {
	runtime?: RuntimeLike;
	/** Id of another extension that exposes its auth. Omit to talk to this extension. */
	extensionId?: string;
}

export interface AuthClient {
	getAccessToken(): Promise<string>;
	getSession(): Promise<ExtensionSession | null>;
	signIn(): Promise<ExtensionSession>;
	signOut(): Promise<SignOutResult>;
}

/** Client side of `exposeAuthToBackground`, for content scripts and popups. */
export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
	const runtime = requireRuntime(options.runtime);

	async function call<T>(method: Method): Promise<T> {
		const request: AuthRequest = { channel: CHANNEL, v: VERSION, method };
		const raw = options.extensionId
			? await runtime.sendMessage(options.extensionId, request)
			: await runtime.sendMessage(request);
		if (
			typeof raw !== "object" ||
			raw === null ||
			(raw as { channel?: unknown }).channel !== CHANNEL
		) {
			throw new ExtensionAuthError("message_rejected", "No answer from the background worker");
		}
		const res = raw as AuthResponse;
		if (!res.ok) throw new ExtensionAuthError(res.error.code, res.error.message);
		return res.data as T;
	}

	return {
		getAccessToken: () => call<string>("getAccessToken"),
		getSession: () => call<ExtensionSession | null>("getSession"),
		signIn: () => call<ExtensionSession>("signIn"),
		signOut: () => call<SignOutResult>("signOut"),
	};
}
