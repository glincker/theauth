// Upstream request and response handling: header hygiene, body limit, timeout.

/** Headers that describe one hop only (RFC 9110 section 7.6.1). */
const HOP_BY_HOP = [
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
];

/** Client supplied headers that claim to describe the proxy chain. Never trusted. */
const CHAIN_HEADERS = [
	"host",
	"forwarded",
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-proto",
	"x-forwarded-port",
	"x-real-ip",
	"x-gateway",
];

export const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;
export const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;

type StreamingInit = RequestInit & { duplex: "half" };

/** Remove hop-by-hop headers, including any the Connection header names. */
export function stripHopByHop(headers: Headers): void {
	const named = (headers.get("connection") ?? "")
		.split(",")
		.map((t) => t.trim().toLowerCase())
		.filter((t) => t.length > 0);
	for (const name of [...HOP_BY_HOP, ...named]) headers.delete(name);
}

/** Parse and check the upstream URL once, at startup. */
export function parseUpstream(upstream: string): URL {
	let url: URL;
	try {
		url = new URL(upstream);
	} catch {
		throw new Error(`Invalid upstream URL "${upstream}"`);
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new Error("The upstream must be an http or https URL");
	}
	if (url.username || url.password) {
		throw new Error("The upstream URL must not contain credentials");
	}
	return url;
}

export interface BodyLimit {
	max: number;
	exceeded: boolean;
}

/** Reject early on Content-Length, then count bytes of a streamed body. */
export function limitBody(
	request: Request,
	limit: BodyLimit,
): { body: ReadableStream<Uint8Array> | null; tooLarge: boolean } {
	const declared = Number(request.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > limit.max) {
		limit.exceeded = true;
		return { body: null, tooLarge: true };
	}
	if (!request.body) return { body: null, tooLarge: false };
	let seen = 0;
	const counter = new TransformStream<Uint8Array, Uint8Array>({
		transform(chunk, controller) {
			seen += chunk.byteLength;
			if (seen > limit.max) {
				limit.exceeded = true;
				controller.error(new Error("Request body too large"));
				return;
			}
			controller.enqueue(chunk);
		},
	});
	return { body: request.body.pipeThrough(counter), tooLarge: false };
}

export interface UpstreamOptions {
	stripAuthHeader: boolean;
	clientIp?: string;
	signal: AbortSignal;
	body: ReadableStream<Uint8Array> | null;
}

export function buildUpstreamRequest(
	request: Request,
	upstream: URL,
	options: UpstreamOptions,
): Request {
	const url = new URL(request.url);
	const target = new URL(upstream.href);
	target.pathname = target.pathname.replace(/\/$/, "") + (url.pathname === "/" ? "" : url.pathname);
	target.search = url.search;
	target.hash = "";

	const headers = new Headers(request.headers);
	stripHopByHop(headers);
	for (const name of CHAIN_HEADERS) headers.delete(name);
	if (options.stripAuthHeader) {
		headers.delete("authorization");
		headers.delete("dpop");
	}
	headers.set("X-Forwarded-Host", url.host);
	headers.set("X-Forwarded-Proto", url.protocol.replace(":", ""));
	if (options.clientIp) headers.set("X-Forwarded-For", options.clientIp);
	headers.set("X-Gateway", "theauth");

	const hasBody = options.body !== null && request.method !== "GET" && request.method !== "HEAD";
	const init: StreamingInit = {
		method: request.method,
		headers,
		body: hasBody ? options.body : null,
		signal: options.signal,
		// The client decides about redirects. Following them here could send the
		// request, and the credentials, to a host the operator never configured.
		redirect: "manual",
		duplex: "half",
	};
	return new Request(target.toString(), init);
}

/**
 * Fetch with a timeout that covers only the wait for response headers. Once
 * the upstream starts answering, the stream is left alone so SSE and long
 * streamable HTTP responses are never cut by this timer.
 */
export async function fetchUpstream(
	upstreamRequest: (signal: AbortSignal) => Request,
	clientSignal: AbortSignal,
	timeoutMs: number,
): Promise<{ response: Response; timedOut: false } | { timedOut: true }> {
	const controller = new AbortController();
	const onClientAbort = () => controller.abort();
	clientSignal.addEventListener("abort", onClientAbort, { once: true });
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		controller.abort();
	}, timeoutMs);
	try {
		const response = await fetch(upstreamRequest(controller.signal));
		return { response, timedOut: false };
	} catch (err) {
		if (timedOut) return { timedOut: true };
		throw err;
	} finally {
		clearTimeout(timer);
		clientSignal.removeEventListener("abort", onClientAbort);
	}
}

/** Point an upstream Location back at the gateway so clients never learn the internal host. */
function rewriteLocation(location: string, upstream: URL, publicOrigin: string): string {
	let parsed: URL;
	try {
		parsed = new URL(location, upstream);
	} catch {
		return location;
	}
	if (parsed.origin !== upstream.origin) return location;
	const base = upstream.pathname.replace(/\/$/, "");
	const path = parsed.pathname.startsWith(base)
		? parsed.pathname.slice(base.length)
		: parsed.pathname;
	return `${publicOrigin}${path.startsWith("/") ? path : `/${path}`}${parsed.search}${parsed.hash}`;
}

export function buildClientResponse(
	upstreamResponse: Response,
	upstream: URL,
	publicOrigin: string,
	extra: Record<string, string>,
): Response {
	const headers = new Headers(upstreamResponse.headers);
	stripHopByHop(headers);
	// fetch has already decoded the body, so these would now be wrong.
	if (headers.has("content-encoding")) {
		headers.delete("content-encoding");
		headers.delete("content-length");
	}
	const location = headers.get("location");
	if (location) headers.set("location", rewriteLocation(location, upstream, publicOrigin));
	if ((headers.get("content-type") ?? "").toLowerCase().startsWith("text/event-stream")) {
		headers.set("Cache-Control", "no-cache, no-transform");
		headers.set("X-Accel-Buffering", "no");
	}
	for (const [key, value] of Object.entries(extra)) headers.set(key, value);
	return new Response(upstreamResponse.body, {
		status: upstreamResponse.status,
		statusText: upstreamResponse.statusText,
		headers,
	});
}
