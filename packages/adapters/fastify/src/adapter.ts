import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import {
	createTheAuthHandler,
	RequestBodyTooLargeError,
	sendWebResponse,
	toWebRequest,
} from "@glinr/theauth/http";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

/** Options for {@link theAuthFastify}: the core handler options. `basePath` defaults to the prefix the plugin is registered under. */
export type TheAuthFastifyOptions = TheAuthHandlerOptions;

/**
 * Fastify plugin serving every theAuth route. Register it under a prefix:
 * `await app.register(theAuthFastify(auth, { mcp }), { prefix: "/api/theauth" })`.
 * Inside the plugin the body is left unparsed, so the handler reads it itself.
 */
export function theAuthFastify(auth: TheAuth, options?: TheAuthFastifyOptions) {
	return async function plugin(fastify: FastifyInstance): Promise<void> {
		// Built once, at registration, when the prefix is known. An unsafe config fails here.
		const handler = createTheAuthHandler(auth, {
			...options,
			basePath: options?.basePath ?? fastify.prefix,
		});
		// Leave every body as a stream for toWebRequest.
		fastify.removeAllContentTypeParsers();
		fastify.addContentTypeParser("*", (_request, payload, done) => done(null, payload));

		const serve = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
			let web: Request;
			try {
				web = await toWebRequest(request.raw, {
					trustProxy: options?.trustedProxy !== undefined,
					maxBodyBytes: options?.maxBodyBytes,
				});
			} catch (err) {
				if (!(err instanceof RequestBodyTooLargeError)) throw err;
				await reply
					.status(413)
					.send({ error: { code: "PAYLOAD_TOO_LARGE", message: err.message } });
				return;
			}
			const response = await handler(web);
			// Headers other plugins (cors, helmet) already set must survive the hijack.
			for (const [name, value] of Object.entries(reply.getHeaders())) {
				if (value !== undefined) reply.raw.setHeader(name, value);
			}
			reply.hijack();
			await sendWebResponse(reply.raw, response);
		};
		fastify.all("/", serve);
		fastify.all("/*", serve);
	};
}
