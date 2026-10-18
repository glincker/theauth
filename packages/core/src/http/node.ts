/** Bridge between Node's http objects and the web-standard handler. Used by the express, fastify and nestjs adapters. */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { TrustedProxyConfig } from "../auth/client-ip.js";
import { resolveClientIp } from "../auth/client-ip.js";

export interface ToWebRequestOptions {
	/** Believe `X-Forwarded-Proto` and `X-Forwarded-Host` when building the URL. Off by default. */
	trustProxy?: boolean;
	/** Largest body to buffer, in bytes. Default 1048576. */
	maxBodyBytes?: number;
}

/** Thrown by {@link toWebRequest} when the body exceeds `maxBodyBytes`. */
export class RequestBodyTooLargeError extends Error {
	readonly status = 413;
	constructor() {
		super("Request body is too large");
		this.name = "RequestBodyTooLargeError";
	}
}

/**
 * Socket remote addresses, kept out of band. Never a header: a client controls every header
 * it sends, but it cannot write into this map.
 */
const peerAddresses = new WeakMap<Request, string>();

/** Remote socket address recorded by {@link toWebRequest}, or undefined for requests that never went through it. */
export function peerAddressOf(request: Request): string | undefined {
	return peerAddresses.get(request);
}

/**
 * Client IP for a request. With `trustedProxy` configured the proxy headers decide (null when absent).
 * Otherwise the recorded socket peer address is used, so a direct Node deployment has an IP and a forged `X-Forwarded-For` is ignored.
 */
export function resolveRequestIp(
	request: Request,
	trustedProxy?: TrustedProxyConfig,
): string | null {
	if (trustedProxy?.trustedHeader || (trustedProxy?.trustedProxyCount ?? 0) > 0) {
		return resolveClientIp(request, trustedProxy);
	}
	return peerAddressOf(request) ?? null;
}

function firstValue(value: string | string[] | undefined): string | undefined {
	const raw = Array.isArray(value) ? value[0] : value;
	return raw?.split(",")[0]?.trim() || undefined;
}

function originOf(req: IncomingMessage, trustProxy: boolean): string {
	const encrypted = (req.socket as { encrypted?: boolean } | undefined)?.encrypted === true;
	const proto =
		(trustProxy ? firstValue(req.headers["x-forwarded-proto"]) : undefined) ??
		(encrypted ? "https" : "http");
	const host =
		(trustProxy ? firstValue(req.headers["x-forwarded-host"]) : undefined) ??
		firstValue(req.headers.host) ??
		"localhost";
	return `${proto === "https" ? "https" : "http"}://${host}`;
}

function toHeaders(req: IncomingMessage): Headers {
	const headers = new Headers();
	for (const [name, value] of Object.entries(req.headers)) {
		if (value === undefined) continue;
		if (Array.isArray(value)) for (const v of value) headers.append(name, v);
		else headers.set(name, value);
	}
	return headers;
}

async function readBody(req: IncomingMessage, maxBytes: number): Promise<Uint8Array> {
	// A body parser (express.json) may already have consumed the stream.
	const parsed = (req as { body?: unknown }).body;
	if (parsed !== undefined && (req.readableEnded || req.complete)) {
		const bytes =
			typeof parsed === "string"
				? new TextEncoder().encode(parsed)
				: parsed instanceof Uint8Array
					? parsed
					: new TextEncoder().encode(JSON.stringify(parsed));
		if (bytes.length > maxBytes) throw new RequestBodyTooLargeError();
		return bytes;
	}
	const chunks: Uint8Array[] = [];
	let size = 0;
	for await (const chunk of req) {
		const bytes =
			typeof chunk === "string" ? new TextEncoder().encode(chunk) : (chunk as Uint8Array);
		size += bytes.length;
		if (size > maxBytes) throw new RequestBodyTooLargeError();
		chunks.push(bytes);
	}
	const out = new Uint8Array(size);
	let offset = 0;
	for (const c of chunks) {
		out.set(c, offset);
		offset += c.length;
	}
	return out;
}

/** Convert a Node request into a web `Request`. Rejects with {@link RequestBodyTooLargeError} over the body limit. */
export async function toWebRequest(
	req: IncomingMessage,
	options: ToWebRequestOptions = {},
): Promise<Request> {
	const path = (req as { originalUrl?: string }).originalUrl ?? req.url ?? "/";
	const url = new URL(path, originOf(req, options.trustProxy === true));
	const method = (req.method ?? "GET").toUpperCase();
	const headers = toHeaders(req);
	const record = (request: Request): Request => {
		const remote = req.socket?.remoteAddress;
		if (remote) peerAddresses.set(request, remote.replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, "$1"));
		return request;
	};
	if (method === "GET" || method === "HEAD") return record(new Request(url, { method, headers }));
	const body = await readBody(req, options.maxBodyBytes ?? 1024 * 1024);
	// The buffered length is authoritative; a stale header would confuse the web layer.
	headers.delete("content-length");
	return record(
		new Request(url, {
			method,
			headers,
			body: body.length > 0 ? new Uint8Array(body) : undefined,
		}),
	);
}

/** Write a web `Response` onto a Node response, streaming the body and honouring backpressure. */
export async function sendWebResponse(res: ServerResponse, response: Response): Promise<void> {
	res.statusCode = response.status;
	if (response.statusText) res.statusMessage = response.statusText;
	const cookies = response.headers.getSetCookie();
	for (const [name, value] of response.headers) {
		if (name.toLowerCase() === "set-cookie") continue;
		res.setHeader(name, value);
	}
	if (cookies.length > 0) res.setHeader("set-cookie", cookies);

	if (!response.body) {
		res.end();
		return;
	}
	const reader = response.body.getReader();
	res.once("close", () => {
		void reader.cancel().catch(() => undefined);
	});
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (res.destroyed) break;
			if (!res.write(value)) {
				await new Promise<void>((resolve) => {
					res.once("drain", resolve);
					res.once("close", resolve);
				});
			}
		}
	} finally {
		if (!res.writableEnded) res.end();
	}
}
