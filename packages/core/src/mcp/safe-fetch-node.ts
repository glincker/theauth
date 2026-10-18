import { classifyIp } from "./cimd-url.js";

/**
 * Pinned connect for the SSRF-safe fetcher on Node and Bun.
 *
 * The platform `fetch` resolves the name a second time when it connects, so a DNS server that answers differently each time (rebinding) can steer the connection to a private address. Here the request goes through `node:https` with a `lookup` that never asks DNS: it returns only the addresses the caller already vetted, after vetting each one again with `classifyIp`. The socket therefore connects to a vetted address and nothing else. TLS still runs against the ORIGINAL hostname (SNI and certificate validation), keep-alive is off, a fresh agent is used per request (so no pooled socket can be reused for another address, and proxy environment variables are never consulted), and one abort signal covers connect, headers and body.
 *
 * `node:https` is only reached through a guarded dynamic import (never at module top level), and never on Workers or Deno, where the caller keeps the `fetch` path.
 */

interface LookupEntry {
	address: string;
	family: 4 | 6;
}
type LookupCallback = (
	err: Error | null,
	address?: string | LookupEntry[],
	family?: number,
) => void;
interface LookupOptions {
	family?: number | string;
	all?: boolean;
}
export type PinnedLookup = (
	hostname: string,
	options: LookupOptions | LookupCallback,
	callback?: LookupCallback,
) => void;

interface IncomingLike {
	statusCode?: number;
	rawHeaders: string[];
	complete?: boolean;
	on(event: string, listener: (...args: never[]) => void): unknown;
	pause(): unknown;
	resume(): unknown;
	destroy(err?: Error): unknown;
}
interface RequestLike {
	on(event: string, listener: (...args: never[]) => void): unknown;
	end(): unknown;
	destroy(err?: Error): unknown;
}
interface RequestOptions {
	method: "GET";
	protocol: "https:";
	host: string;
	port: number;
	path: string;
	headers: Record<string, string>;
	agent: unknown;
	lookup: PinnedLookup;
	servername?: string;
	rejectUnauthorized: true;
	ca?: string;
	signal: AbortSignal;
}
export interface NodeHttpsModule {
	request(options: RequestOptions, onResponse: (res: IncomingLike) => void): RequestLike;
	Agent: new (options: { keepAlive: false; maxSockets: number }) => { destroy(): void };
}

let httpsModule: Promise<NodeHttpsModule | null> | undefined;

/** True on runtimes where we may take over the connection: Node and Bun, never Deno or Workers. */
function runtimeAllowsNodeHttps(): boolean {
	const g = globalThis as {
		Deno?: unknown;
		navigator?: { userAgent?: string };
		process?: { versions?: { node?: string } };
	};
	if (g.Deno !== undefined) return false;
	if (g.navigator?.userAgent?.startsWith("Cloudflare-Workers")) return false;
	return typeof g.process?.versions?.node === "string";
}

/** Guarded dynamic import. The specifier is built at runtime so edge bundlers do not resolve it, and any failure yields null (the caller keeps the fetch path). */
export function loadNodeHttps(): Promise<NodeHttpsModule | null> {
	httpsModule ??= (async () => {
		if (!runtimeAllowsNodeHttps()) return null;
		try {
			const spec = ["node", "https"].join(":");
			const mod = (await import(/* @vite-ignore */ spec)) as Partial<NodeHttpsModule>;
			return typeof mod.request === "function" && typeof mod.Agent === "function"
				? (mod as NodeHttpsModule)
				: null;
		} catch {
			return null;
		}
	})();
	return httpsModule;
}

/** TEST ONLY. `null` simulates a runtime without node:https, a module injects a fake, `undefined` restores detection. */
export function setNodeHttpsForTests(mod: NodeHttpsModule | null | undefined): void {
	httpsModule = mod === undefined ? undefined : Promise.resolve(mod);
}

function plainAddress(address: string): string {
	return address.trim().replace(/^\[|\]$/g, "");
}

/** Builds the `lookup` handed to node:https. It never queries DNS. Every pinned address must pass `vet` again at connect time; one bad address refuses the whole answer (none skipped). Handles both the single address and the `all: true` shapes, and the `family` filter used by Node's family fallback. */
export function createPinnedLookup(
	addresses: readonly string[],
	vet: (address: string) => boolean,
	onRefused: (detail: string) => void,
): PinnedLookup {
	const pinned = addresses.map(plainAddress);
	return (_hostname, options, callback) => {
		const cb = typeof options === "function" ? options : callback;
		const opts: LookupOptions = typeof options === "function" ? {} : options;
		if (!cb) return;
		const refuse = (detail: string, code: string): void => {
			onRefused(detail);
			cb(Object.assign(new Error(detail), { code }));
		};
		if (pinned.length === 0) return refuse("no pinned address", "ENOTFOUND");
		for (const a of pinned) {
			if (!vet(a)) return refuse("pinned address is not public at connect", "EACCES");
		}
		const entries: LookupEntry[] = pinned.map((address) => ({
			address,
			family: address.includes(":") ? 6 : 4,
		}));
		const want = Number(opts.family);
		const usable = want === 4 || want === 6 ? entries.filter((e) => e.family === want) : entries;
		const first = usable[0];
		if (!first) return refuse("no pinned address for the requested family", "ENOTFOUND");
		if (opts.all === true) cb(null, usable);
		else cb(null, first.address, first.family);
	};
}

/** Pinned addresses must be public, unless a test explicitly allows loopback. */
export function publicVetter(allowLoopback: boolean): (address: string) => boolean {
	return (address) => (allowLoopback ? true : classifyIp(address) === "public");
}

export class PinnedConnectRefused extends Error {}

export interface PinnedFetchArgs {
	url: URL;
	addresses: readonly string[];
	vet: (address: string) => boolean;
	signal: AbortSignal;
	headers: Record<string, string>;
	/** TEST ONLY. Extra CA so a local self signed server validates. */
	ca?: string;
}

function toBodyStream(res: IncomingLike): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>({
		start(controller) {
			res.on("data", ((chunk: Uint8Array) => {
				controller.enqueue(new Uint8Array(chunk));
				if ((controller.desiredSize ?? 1) <= 0) res.pause();
			}) as (...args: never[]) => void);
			res.on("end", (() => controller.close()) as (...args: never[]) => void);
			res.on("error", ((err: Error) => controller.error(err)) as (...args: never[]) => void);
			res.on("close", (() => {
				if (res.complete !== true) controller.error(new Error("connection closed early"));
			}) as (...args: never[]) => void);
		},
		pull() {
			res.resume();
		},
		cancel() {
			res.destroy();
		},
	});
}

function toHeaders(raw: string[]): Headers {
	const headers = new Headers();
	for (let i = 0; i + 1 < raw.length; i += 2) {
		try {
			headers.append(raw[i] as string, raw[i + 1] as string);
		} catch {
			// Skip header lines the Headers class refuses.
		}
	}
	return headers;
}

/** GET over node:https pinned to vetted addresses. Resolves with a Response (body streamed). Rejects with PinnedConnectRefused when an address was refused at connect, otherwise with the transport error. */
export async function pinnedHttpsGet(
	https: NodeHttpsModule,
	args: PinnedFetchArgs,
): Promise<Response> {
	const { url, signal } = args;
	let refused: string | null = null;
	const lookup = createPinnedLookup(args.addresses, args.vet, (d) => {
		refused = d;
	});
	// A new agent per request: no keep-alive, no pooled socket, no proxy handling.
	const agent = new https.Agent({ keepAlive: false, maxSockets: 1 });
	const host = url.hostname.replace(/^\[|\]$/g, "");
	const isIp = host.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
	return new Promise<Response>((resolve, reject) => {
		const req = https.request(
			{
				method: "GET",
				protocol: "https:",
				host,
				port: url.port ? Number(url.port) : 443,
				path: `${url.pathname}${url.search}`,
				headers: { ...args.headers, Connection: "close", Host: url.host },
				agent,
				lookup,
				...(isIp ? {} : { servername: host }),
				rejectUnauthorized: true,
				...(args.ca !== undefined ? { ca: args.ca } : {}),
				signal,
			},
			(res) => {
				const status = res.statusCode ?? 0;
				const headers = toHeaders(res.rawHeaders);
				if (status !== 200) {
					res.destroy();
					agent.destroy();
					resolve(
						new Response(null, { status: status >= 200 && status <= 599 ? status : 502, headers }),
					);
					return;
				}
				resolve(new Response(toBodyStream(res), { status, headers }));
			},
		);
		req.on("error", ((err: Error) => {
			agent.destroy();
			reject(refused !== null ? new PinnedConnectRefused(refused) : err);
		}) as (...a: never[]) => void);
		signal.addEventListener("abort", () => agent.destroy(), { once: true });
		req.end();
	});
}
