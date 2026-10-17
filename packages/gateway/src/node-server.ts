import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { Readable } from "node:stream";

type Handler = (request: Request) => Promise<Response>;

function plain(res: ServerResponse, status: number, message: string): void {
	if (res.headersSent) {
		res.destroy();
		return;
	}
	res.writeHead(status, { "Content-Type": "application/json" });
	res.end(
		JSON.stringify({ error: { code: status === 400 ? "BAD_REQUEST" : "INTERNAL", message } }),
	);
}

function toWebRequest(req: IncomingMessage, signal: AbortSignal): Request {
	const host = req.headers.host ?? "localhost";
	const url = new URL(`http://${host}${req.url ?? "/"}`);
	const headers = new Headers();
	for (const [k, v] of Object.entries(req.headers)) {
		if (v === undefined) continue;
		if (Array.isArray(v)) for (const val of v) headers.append(k, val);
		else headers.set(k, v);
	}
	const method = req.method ?? "GET";
	const hasBody =
		method !== "GET" &&
		method !== "HEAD" &&
		(req.headers["content-length"] !== undefined || req.headers["transfer-encoding"] !== undefined);
	const init: RequestInit & { duplex: "half" } = {
		method,
		headers,
		// Streamed, never buffered here. The size limit is enforced in the handler.
		body: hasBody ? (Readable.toWeb(req) as ReadableStream<Uint8Array>) : null,
		signal,
		duplex: "half",
	};
	return new Request(url, init);
}

function responseHeaders(response: Response): Array<[string, string]> {
	const out: Array<[string, string]> = [];
	response.headers.forEach((value, key) => {
		if (key !== "set-cookie") out.push([key, value]);
	});
	for (const cookie of response.headers.getSetCookie()) out.push(["set-cookie", cookie]);
	return out;
}

async function pipeResponse(res: ServerResponse, response: Response): Promise<void> {
	res.writeHead(response.status, response.statusText, responseHeaders(response).flat());
	res.flushHeaders();
	if (!response.body) {
		res.end();
		return;
	}
	const reader = response.body.getReader();
	res.on("close", () => {
		void reader.cancel().catch(() => undefined);
	});
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (res.destroyed) break;
			// Honour backpressure so a slow client cannot make the gateway buffer a stream.
			if (!res.write(value)) {
				await new Promise<void>((resolve) => {
					const done2 = () => {
						res.off("drain", done2);
						res.off("close", done2);
						resolve();
					};
					res.on("drain", done2);
					res.on("close", done2);
				});
			}
		}
	} finally {
		reader.releaseLock();
	}
	res.end();
}

export function startServer(handler: Handler, port: number): Promise<Server> {
	const server = createServer((req, res) => {
		const abort = new AbortController();
		res.on("close", () => {
			if (!res.writableFinished) abort.abort();
		});
		let request: Request;
		try {
			request = toWebRequest(req, abort.signal);
		} catch {
			plain(res, 400, "Malformed request");
			return;
		}
		handler(request)
			.then((response) => pipeResponse(res, response))
			.catch(() => plain(res, 500, "Internal gateway error"));
	});
	return new Promise((resolve) => {
		server.listen(port, () => resolve(server));
	});
}
