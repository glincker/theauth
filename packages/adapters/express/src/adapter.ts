import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandler, TheAuthHandlerOptions } from "@glinr/theauth/http";
import {
	createTheAuthHandler,
	RequestBodyTooLargeError,
	sendWebResponse,
	toWebRequest,
} from "@glinr/theauth/http";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { Router } from "express";

/** Options for {@link theAuthExpress}: the core handler options. `basePath` defaults to where the router is mounted. */
export type TheAuthExpressOptions = TheAuthHandlerOptions;

/** Upper bound on distinct mount points served by one adapter instance. */
const MAX_MOUNTS = 32;

const FORM_TYPE = /^application\/x-www-form-urlencoded/i;

/** Express `urlencoded()` leaves an object behind; the web layer needs the encoded string back. */
function restoreFormBody(req: Request): void {
	const body: unknown = req.body;
	if (body && typeof body === "object" && FORM_TYPE.test(req.headers["content-type"] ?? "")) {
		req.body = new URLSearchParams(body as Record<string, string>).toString();
	}
}

/**
 * Express router serving every theAuth route. Mount it anywhere
 * (`app.use("/api/theauth", theAuthExpress(auth, { mcp }))`); body parsers before it are fine.
 */
export function theAuthExpress(auth: TheAuth, options?: TheAuthExpressOptions): Router {
	const router = Router();
	// Built now so an unsafe config fails at startup. Used when the router is mounted at the root.
	const handlers = new Map<string, TheAuthHandler>([
		[
			(options?.basePath ?? "").toLowerCase(),
			createTheAuthHandler(auth, { ...options, basePath: options?.basePath ?? "" }),
		],
	]);
	const handle: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
		try {
			const mount = options?.basePath ?? req.baseUrl;
			// Key on the lowercased mount: Express matches mounts case-insensitively, so every spelling of
			// the same mount must share one handler. The cache is also bounded, never grown by request data.
			const key = mount.toLowerCase();
			let handler = handlers.get(key);
			if (!handler) {
				if (handlers.size >= MAX_MOUNTS) {
					res.status(404).json({ error: { code: "NOT_FOUND", message: "Not found" } });
					return;
				}
				handler = createTheAuthHandler(auth, { ...options, basePath: mount });
				handlers.set(key, handler);
			}
			restoreFormBody(req);
			const web = await toWebRequest(req, {
				trustProxy: options?.trustedProxy !== undefined,
				maxBodyBytes: options?.maxBodyBytes,
			});
			await sendWebResponse(res, await handler(web));
		} catch (err) {
			if (err instanceof RequestBodyTooLargeError) {
				res.status(413).json({ error: { code: "PAYLOAD_TOO_LARGE", message: err.message } });
				return;
			}
			next(err);
		}
	};
	router.use(handle);
	return router;
}
