import { createConcurrencyLimiter } from "./dns-limiter.js";

/** DNS plumbing for the SSRF-safe fetcher: the guarded node:dns import, a concurrency cap on the threadpool backed lookup, and the shared deadline helper. */

type DnsModule = {
	lookup: (h: string, o: { all: true; verbatim: true }) => Promise<Array<{ address: string }>>;
};

let dnsModule: Promise<DnsModule | null> | undefined;

/** Guarded dynamic import: the specifier is built at runtime so bundlers for edge targets do not resolve it, and a failed import (Workers) yields null instead of throwing. */
export function loadNodeDns(): Promise<DnsModule | null> {
	dnsModule ??= (async () => {
		try {
			const spec = ["node", "dns/promises"].join(":");
			const mod = (await import(/* @vite-ignore */ spec)) as DnsModule;
			return typeof mod.lookup === "function" ? mod : null;
		} catch {
			return null;
		}
	})();
	return dnsModule;
}

/** TEST ONLY. `null` simulates a runtime without node:dns, `undefined` restores detection. */
export function setNodeDnsForTests(mod: DnsModule | null | undefined): void {
	dnsModule = mod === undefined ? undefined : Promise.resolve(mod);
}

/** `dns.lookup` runs getaddrinfo on the libuv threadpool (4 threads by default), shared with crypto, zlib and fs. Keep lookups to a few so a name server that never answers cannot starve the process. */
const lookupLimiter = createConcurrencyLimiter(3, 32);

/** Default resolver: Node's `dns.lookup` with `all: true`, loaded lazily and concurrency capped. Throws when this runtime has no `node:dns` (the caller fails closed). */
export async function defaultDnsResolver(hostname: string): Promise<string[]> {
	const dns = await loadNodeDns();
	if (!dns) throw new Error("node:dns is not available on this runtime");
	const records = await lookupLimiter.run(() =>
		dns.lookup(hostname, { all: true, verbatim: true }),
	);
	return records.map((r) => r.address);
}

export class DeadlineError extends Error {}

/** Resolves with `p`, or rejects with DeadlineError when the budget ends first. */
export function withDeadline<T>(p: Promise<T>, deadline: number): Promise<T> {
	const left = deadline - Date.now();
	if (left <= 0) {
		p.catch(() => undefined);
		return Promise.reject(new DeadlineError("deadline"));
	}
	return new Promise<T>((resolve, reject) => {
		const t = setTimeout(() => reject(new DeadlineError("deadline")), left);
		p.then(
			(v) => {
				clearTimeout(t);
				resolve(v);
			},
			(e: unknown) => {
				clearTimeout(t);
				reject(e);
			},
		);
	});
}
