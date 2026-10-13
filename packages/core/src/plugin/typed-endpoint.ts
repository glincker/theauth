/**
 * Typed plugin endpoints.
 *
 * `defineEndpoint` validates path params, query and JSON body with zod before
 * the handler runs, and records the shapes in a type so a client can call the
 * route with full inference (see `createEndpointClient` in the client package).
 * The result is an ordinary `PluginEndpoint`, so `ctx.addEndpoint` takes it.
 */

import type { z } from "zod";
import type { EndpointContext, PluginEndpoint } from "./types.js";

type Method = PluginEndpoint["method"];

/** Query parameter the router uses to pass `:name` path segments. */
const PARAM_PREFIX = "_param_";

type Schema = z.ZodTypeAny | undefined;

/** Parsed output of a schema, or `Fallback` when the endpoint declares none. */
type Out<S, Fallback> = S extends z.ZodTypeAny ? z.output<S> : Fallback;

export interface EndpointSchemas {
	params?: z.ZodTypeAny;
	query?: z.ZodTypeAny;
	body?: z.ZodTypeAny;
	response?: z.ZodTypeAny;
}

export interface EndpointInput<SP extends Schema, SQ extends Schema, SB extends Schema> {
	params: Out<SP, Record<string, string>>;
	query: Out<SQ, Record<string, string>>;
	body: Out<SB, undefined>;
}

export interface EndpointDefinition<
	M extends Method,
	P extends string,
	SP extends Schema,
	SQ extends Schema,
	SB extends Schema,
	SR extends Schema,
	R,
> {
	method: M;
	path: P;
	params?: SP;
	query?: SQ;
	body?: SB;
	response?: SR;
	metadata?: PluginEndpoint["metadata"];
	handler: (
		input: EndpointInput<SP, SQ, SB>,
		ctx: EndpointContext & { request: Request },
	) => Promise<R | Response>;
}

/** Phantom carrier for the client side types. Never present at runtime. */
export interface EndpointTypes<SP, SQ, SB, SR, R> {
	params: Out<SP, undefined>;
	query: Out<SQ, undefined>;
	body: Out<SB, undefined>;
	response: SR extends z.ZodTypeAny ? z.output<SR> : R;
}

export type TypedEndpoint<
	M extends Method = Method,
	P extends string = string,
	SP = unknown,
	SQ = unknown,
	SB = unknown,
	SR = unknown,
	R = unknown,
> = Omit<PluginEndpoint, "method" | "path"> & {
	method: M;
	path: P;
	/** Type carrier only. */
	readonly $types?: EndpointTypes<SP, SQ, SB, SR, R>;
};

function jsonError(status: number, code: string, message: string, extra?: object): Response {
	return new Response(JSON.stringify({ error: { code, message, ...extra } }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

export function defineEndpoint<
	const M extends Method,
	const P extends string,
	SP extends Schema = undefined,
	SQ extends Schema = undefined,
	SB extends Schema = undefined,
	SR extends Schema = undefined,
	R = unknown,
>(definition: EndpointDefinition<M, P, SP, SQ, SB, SR, R>): TypedEndpoint<M, P, SP, SQ, SB, SR, R> {
	const { params, query, body, response, handler, ...endpoint } = definition;

	return {
		...endpoint,
		async handler(request, ctx) {
			const url = new URL(request.url);
			const rawParams: Record<string, string> = {};
			const rawQuery: Record<string, string> = {};
			for (const [key, value] of url.searchParams) {
				if (key.startsWith(PARAM_PREFIX)) rawParams[key.slice(PARAM_PREFIX.length)] = value;
				else rawQuery[key] = value;
			}

			const issues: Array<{ where: string; path: string; message: string }> = [];
			const parse = (where: string, schema: z.ZodTypeAny | undefined, value: unknown): unknown => {
				if (!schema) return value;
				const result = schema.safeParse(value);
				if (result.success) return result.data;
				for (const issue of result.error.issues) {
					issues.push({ where, path: issue.path.join("."), message: issue.message });
				}
				return undefined;
			};

			let rawBody: unknown;
			if (body) {
				try {
					rawBody = await request.json();
				} catch {
					return jsonError(400, "INVALID_JSON", "Request body must be valid JSON");
				}
			}

			const input = {
				params: parse("params", params, rawParams),
				query: parse("query", query, rawQuery),
				body: parse("body", body, rawBody),
			} as EndpointInput<SP, SQ, SB>;
			if (issues.length > 0) {
				return jsonError(400, "INVALID_INPUT", "Request did not match the endpoint schema", {
					issues,
				});
			}

			const result = await handler(input, { ...ctx, request });
			if (result instanceof Response) return result;
			if (response) {
				const checked = response.safeParse(result);
				if (!checked.success) {
					return jsonError(500, "INVALID_RESPONSE", "Endpoint produced an invalid response");
				}
			}
			return new Response(JSON.stringify(result), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		},
	};
}

/**
 * Route map for a set of endpoints, keyed `"METHOD /path"`. Hand it to the
 * client package: `createEndpointClient<ApiOf<typeof endpoints>>(...)`.
 */
export type ApiOf<T extends readonly TypedEndpoint[]> = {
	[E in T[number] as E extends { method: infer M extends string; path: infer P extends string }
		? `${M} ${P}`
		: never]: E extends { readonly $types?: infer X } ? NonNullable<X> : never;
};
