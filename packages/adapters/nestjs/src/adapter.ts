import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandler, TheAuthHandlerOptions } from "@glinr/theauth/http";
import {
	createTheAuthHandler,
	RequestBodyTooLargeError,
	sendWebResponse,
	toWebRequest,
} from "@glinr/theauth/http";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { NextFunction, Request, Response } from "express";

/** Options for {@link theAuthMiddleware}: the core handler options plus the `theauth` instance. `basePath` defaults to where the middleware is mounted. */
export interface TheAuthNestjsOptions extends TheAuthHandlerOptions {
	theauth: TheAuth;
}

export type TheAuthMiddleware = (req: Request, res: Response, next: NextFunction) => Promise<void>;

const FORM_TYPE = /^application\/x-www-form-urlencoded/i;

/** Express `urlencoded()` leaves an object behind; the web layer needs the encoded string back. */
function restoreFormBody(req: Request): void {
	const body: unknown = req.body;
	if (body && typeof body === "object" && FORM_TYPE.test(req.headers["content-type"] ?? "")) {
		req.body = new URLSearchParams(body as Record<string, string>).toString();
	}
}

/** Express-style middleware serving every theAuth route. Used by `TheAuthModule` and by Express-backed Nest apps. */
export function theAuthMiddleware(options: TheAuthNestjsOptions): TheAuthMiddleware {
	const { theauth, ...handlerOptions } = options;
	// Built now so an unsafe config fails at startup. Used when mounted at the root.
	const handlers = new Map<string, TheAuthHandler>([
		[
			options.basePath ?? "",
			createTheAuthHandler(theauth, { ...handlerOptions, basePath: options.basePath ?? "" }),
		],
	]);
	return async (req, res, next) => {
		try {
			const mount = options.basePath ?? req.baseUrl;
			let handler = handlers.get(mount);
			if (!handler) {
				handler = createTheAuthHandler(theauth, { ...handlerOptions, basePath: mount });
				handlers.set(mount, handler);
			}
			restoreFormBody(req);
			const web = await toWebRequest(req, {
				trustProxy: options.trustedProxy !== undefined,
				maxBodyBytes: options.maxBodyBytes,
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
}

/** Same middleware with positional arguments, for apps that mount it by hand. */
export function buildTheAuthRouter(
	auth: TheAuth,
	mcp?: McpAuthModule,
	security?: TheAuthHandlerOptions,
): TheAuthMiddleware {
	return theAuthMiddleware({ ...security, theauth: auth, mcp });
}
