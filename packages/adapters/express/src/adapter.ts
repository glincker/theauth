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
			options?.basePath ?? "",
			createTheAuthHandler(auth, { ...options, basePath: options?.basePath ?? "" }),
		],
	]);
	const handle: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
		try {
			const mount = options?.basePath ?? req.baseUrl;
			let handler = handlers.get(mount);
			if (!handler) {
				handler = createTheAuthHandler(auth, { ...options, basePath: mount });
				handlers.set(mount, handler);
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
