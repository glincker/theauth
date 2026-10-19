import type { SpiffeBundle } from "./bundle.js";
import { bundleFromRoots, parseSpiffeBundle } from "./bundle.js";
import { parseTrustDomain } from "./spiffe-id.js";

/**
 * Where to fetch a trust bundle (SPIFFE Federation, bundle endpoint). `https_web` endpoints are
 * served with a public web PKI certificate, so the global `fetch` works. An `https_spiffe` endpoint
 * authenticates with an X.509-SVID and needs your own `fetch` that does mutual TLS against your bootstrap bundle.
 */
export interface SpiffeBundleEndpoint {
	/** Must be https. */
	url: string;
	fetch?: typeof fetch;
	/** Default 5000. */
	timeoutMs?: number;
	/** Largest accepted body. Default 1 MiB. */
	maxBytes?: number;
	/** Never poll faster than this, whatever `spiffe_refresh_hint` says. Default 60. */
	minRefreshSeconds?: number;
	/** Used when the bundle has no `spiffe_refresh_hint`. Default 300. */
	defaultRefreshSeconds?: number;
	/** Stop trusting the last good bundle when this many seconds passed without a successful refresh. Default 86400. */
	maxStaleSeconds?: number;
}

export interface SpiffeTrustDomainConfig {
	/** A bundle document (object or JSON text), used first and as the fallback until a refresh succeeds. */
	bundle?: unknown;
	/** PEM or base64 DER root certificates, for X.509-SVIDs only. */
	roots?: string[];
	endpoint?: SpiffeBundleEndpoint;
}

export type BundleRefresh = { ok: true; changed: boolean } | { ok: false; reason: string };

interface Entry {
	bundle: SpiffeBundle | null;
	/** ms of the last successful load. Static bundles never go stale unless an endpoint is set. */
	loadedAt: number;
	nextAttempt: number;
	endpoint?: SpiffeBundleEndpoint;
	inflight?: Promise<BundleRefresh>;
}

const DEFAULTS = {
	timeoutMs: 5000,
	maxBytes: 1_048_576,
	minRefreshSeconds: 60,
	defaultRefreshSeconds: 300,
	maxStaleSeconds: 86_400,
};
const MAX_REFRESH_SECONDS = 86_400;

async function readLimited(res: Response, max: number): Promise<string | null> {
	const declared = Number(res.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > max) return null;
	if (!res.body) {
		const text = await res.text();
		return new TextEncoder().encode(text).length > max ? null : text;
	}
	const reader = res.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.length;
		if (size > max) {
			await reader.cancel();
			return null;
		}
		chunks.push(value);
	}
	const all = new Uint8Array(size);
	let at = 0;
	for (const c of chunks) {
		all.set(c, at);
		at += c.length;
	}
	return new TextDecoder().decode(all);
}

/**
 * Holds the trust bundle of each configured trust domain and keeps it fresh. No timers: a bundle is
 * refreshed on demand when `get` finds it older than its refresh hint, so serverless runtimes work.
 * A failed refresh keeps the last good bundle until `maxStaleSeconds`, then the domain fails closed.
 */
export function createBundleStore(
	domains: Record<string, SpiffeTrustDomainConfig>,
	now: () => number = Date.now,
) {
	const entries = new Map<string, Entry>();
	for (const [name, config] of Object.entries(domains)) {
		const td = parseTrustDomain(name);
		if (!td) throw new Error(`SPIFFE: "${name}" is not a valid trust domain name`);
		if (entries.has(td)) throw new Error(`SPIFFE: trust domain "${td}" is configured twice`);
		if (!config.bundle && !config.roots && !config.endpoint) {
			throw new Error(`SPIFFE: trust domain "${td}" needs a bundle, roots or an endpoint`);
		}
		if (config.endpoint && !/^https:\/\//i.test(config.endpoint.url)) {
			throw new Error(`SPIFFE: the bundle endpoint of "${td}" must be https`);
		}
		let bundle: SpiffeBundle | null = null;
		if (config.bundle !== undefined || config.roots) {
			const parsed =
				config.bundle !== undefined
					? parseSpiffeBundle(td, config.bundle)
					: bundleFromRoots(td, config.roots ?? []);
			if (!parsed.ok) throw new Error(`SPIFFE: trust domain "${td}": ${parsed.reason}`);
			bundle = parsed.bundle;
			if (config.bundle !== undefined && config.roots) {
				const extra = bundleFromRoots(td, config.roots);
				if (!extra.ok) throw new Error(`SPIFFE: trust domain "${td}": ${extra.reason}`);
				bundle.x509Authorities.push(...extra.bundle.x509Authorities);
			}
		}
		entries.set(td, {
			bundle,
			loadedAt: now(),
			nextAttempt: 0,
			...(config.endpoint && { endpoint: config.endpoint }),
		});
	}

	function setting<K extends keyof typeof DEFAULTS>(e: Entry, key: K): number {
		return e.endpoint?.[key] ?? DEFAULTS[key];
	}

	async function fetchBundle(td: string, e: Entry): Promise<BundleRefresh> {
		const endpoint = e.endpoint;
		if (!endpoint) return { ok: false, reason: "No bundle endpoint configured" };
		const doFetch = endpoint.fetch ?? globalThis.fetch;
		try {
			const res = await doFetch(endpoint.url, {
				method: "GET",
				redirect: "error",
				headers: { accept: "application/json" },
				signal: AbortSignal.timeout(setting(e, "timeoutMs")),
			});
			if (!res.ok) return { ok: false, reason: `Bundle endpoint answered ${res.status}` };
			const text = await readLimited(res, setting(e, "maxBytes"));
			if (text === null) return { ok: false, reason: "Bundle response is too large" };
			const parsed = parseSpiffeBundle(td, text);
			if (!parsed.ok) return { ok: false, reason: parsed.reason };
			const current = e.bundle;
			if (current?.sequence !== undefined) {
				// Rollback guard: a lower or missing sequence could replay an older authority set.
				if (parsed.bundle.sequence === undefined || parsed.bundle.sequence < current.sequence) {
					return { ok: false, reason: "Bundle sequence went backwards" };
				}
			}
			const changed = current?.sequence !== parsed.bundle.sequence || !current;
			e.bundle = parsed.bundle;
			return { ok: true, changed };
		} catch {
			return { ok: false, reason: "Bundle endpoint could not be reached" };
		}
	}

	async function refresh(trustDomain: string): Promise<BundleRefresh> {
		const td = parseTrustDomain(trustDomain);
		const e = td ? entries.get(td) : undefined;
		if (!td || !e) return { ok: false, reason: "Unknown trust domain" };
		if (e.inflight) return e.inflight;
		e.inflight = fetchBundle(td, e)
			.then((result) => {
				const t = now();
				if (result.ok) {
					e.loadedAt = t;
					const hint = e.bundle?.refreshHintSeconds ?? setting(e, "defaultRefreshSeconds");
					const seconds = Math.min(
						Math.max(hint, setting(e, "minRefreshSeconds")),
						MAX_REFRESH_SECONDS,
					);
					e.nextAttempt = t + seconds * 1000;
				} else {
					e.nextAttempt = t + setting(e, "minRefreshSeconds") * 1000;
				}
				return result;
			})
			.finally(() => {
				e.inflight = undefined;
			});
		return e.inflight;
	}

	/** The current bundle of a trust domain, or null when it is unknown, never loaded or stale. */
	async function get(trustDomain: string): Promise<SpiffeBundle | null> {
		const e = entries.get(trustDomain);
		if (!e) return null;
		if (e.endpoint && now() >= e.nextAttempt) await refresh(trustDomain);
		if (!e.bundle) return null;
		if (e.endpoint && now() - e.loadedAt > setting(e, "maxStaleSeconds") * 1000) return null;
		return e.bundle;
	}

	return { get, refresh, trustDomains: () => [...entries.keys()] };
}

export type SpiffeBundleStore = ReturnType<typeof createBundleStore>;
