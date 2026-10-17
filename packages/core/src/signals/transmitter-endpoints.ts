/**
 * HTTP endpoints for the Shared Signals transmitter (SSF 1.0 section 8 and RFC 8936 polling). Built with `defineEndpoint` so inputs are validated by zod and the shapes are available to the typed client.
 */

import { z } from "zod";
import { json } from "../plugin/helpers.js";
import { defineEndpoint } from "../plugin/typed-endpoint.js";
import type { PluginEndpoint } from "../plugin/types.js";
import { parseSubject } from "./subjects.js";
import type { Transmitter } from "./transmitter.js";
import type { StoredStream } from "./types.js";
import { DELIVERY_POLL, DELIVERY_PUSH } from "./types.js";

const noStore = { "Cache-Control": "no-store" };

function problem(status: number, err: string, description: string): Response {
	return new Response(JSON.stringify({ err, description }), {
		status,
		headers: { "Content-Type": "application/json", ...noStore },
	});
}

const deliverySchema = z.object({
	method: z.enum([DELIVERY_PUSH, DELIVERY_POLL]),
	endpoint_url: z.string().max(2048).optional(),
	authorization_header: z.string().max(4096).optional(),
});

const streamBody = z.object({
	events_requested: z.array(z.string().max(512)).max(64),
	delivery: deliverySchema,
	aud: z.array(z.string().max(512)).max(16).optional(),
	description: z.string().max(1024).optional(),
	min_verification_interval: z.number().int().min(0).optional(),
});

const patchBody = z.object({
	stream_id: z.string(),
	events_requested: z.array(z.string().max(512)).max(64).optional(),
	delivery: deliverySchema.optional(),
	description: z.string().max(1024).optional(),
	min_verification_interval: z.number().int().min(0).optional(),
});

const streamIdQuery = z.object({ stream_id: z.string().min(1).max(256).optional() });
const requiredStreamIdQuery = z.object({ stream_id: z.string().min(1).max(256) });

export function createTransmitterEndpoints(tx: Transmitter): PluginEndpoint[] {
	const limit = (max: number) => ({ rateLimit: { window: 60, max } });

	/** Resolve caller and the stream they own, or an error response. */
	async function owned(
		request: Request,
		streamId: string,
	): Promise<{ stream: StoredStream } | { response: Response }> {
		const caller = await tx.config.authenticate(request);
		if (!caller) return { response: problem(401, "authentication_failed", "unauthenticated") };
		const stream = await tx.store.getStream(streamId);
		// Same answer for missing and foreign streams so ids are not probeable.
		if (!stream || stream.owner !== caller.id) {
			return { response: problem(404, "not_found", "stream not found") };
		}
		return { stream };
	}

	const wellKnown = defineEndpoint({
		method: "GET",
		path: "/.well-known/ssf-configuration",
		metadata: { ...limit(120), description: "SSF transmitter configuration metadata" },
		async handler() {
			return new Response(JSON.stringify(tx.metadata()), {
				status: 200,
				headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
			});
		},
	});

	const createStream = defineEndpoint({
		method: "POST",
		path: "/ssf/stream",
		body: streamBody,
		metadata: { ...limit(30), description: "SSF create stream" },
		async handler({ body }, ctx) {
			const caller = await tx.config.authenticate(ctx.request);
			if (!caller) return problem(401, "authentication_failed", "unauthenticated");
			const result = await tx.createStream({
				owner: caller.id,
				eventsRequested: body.events_requested,
				delivery: body.delivery,
				aud: body.aud,
				description: body.description,
				minVerificationInterval: body.min_verification_interval,
			});
			if (!result.ok) return problem(400, result.code, result.message);
			return new Response(JSON.stringify(tx.toConfiguration(result.value)), {
				status: 201,
				headers: { "Content-Type": "application/json", ...noStore },
			});
		},
	});

	const readStream = defineEndpoint({
		method: "GET",
		path: "/ssf/stream",
		query: streamIdQuery,
		metadata: { ...limit(120), description: "SSF read stream configuration" },
		async handler({ query }, ctx) {
			if (query.stream_id) {
				const found = await owned(ctx.request, query.stream_id);
				if ("response" in found) return found.response;
				return json(tx.toConfiguration(found.stream));
			}
			const caller = await tx.config.authenticate(ctx.request);
			if (!caller) return problem(401, "authentication_failed", "unauthenticated");
			const streams = await tx.store.listStreams(caller.id);
			return json(streams.map((s) => tx.toConfiguration(s)));
		},
	});

	const patchStream = defineEndpoint({
		method: "PATCH",
		path: "/ssf/stream",
		body: patchBody,
		metadata: { ...limit(30), description: "SSF update stream configuration" },
		async handler({ body }, ctx) {
			const found = await owned(ctx.request, body.stream_id);
			if ("response" in found) return found.response;
			const result = await tx.updateStream(found.stream, {
				eventsRequested: body.events_requested,
				delivery: body.delivery,
				description: body.description,
				minVerificationInterval: body.min_verification_interval,
			});
			if (!result.ok) return problem(400, result.code, result.message);
			return json(tx.toConfiguration(result.value));
		},
	});

	const replaceStream = defineEndpoint({
		method: "PUT",
		path: "/ssf/stream",
		body: patchBody.extend({
			events_requested: z.array(z.string().max(512)).max(64),
			delivery: deliverySchema,
		}),
		metadata: { ...limit(30), description: "SSF replace stream configuration" },
		async handler({ body }, ctx) {
			const found = await owned(ctx.request, body.stream_id);
			if ("response" in found) return found.response;
			const result = await tx.updateStream(found.stream, {
				eventsRequested: body.events_requested,
				delivery: body.delivery,
				description: body.description ?? "",
				minVerificationInterval: body.min_verification_interval,
			});
			if (!result.ok) return problem(400, result.code, result.message);
			return json(tx.toConfiguration(result.value));
		},
	});

	const deleteStream = defineEndpoint({
		method: "DELETE",
		path: "/ssf/stream",
		query: requiredStreamIdQuery,
		metadata: { ...limit(30), description: "SSF delete stream" },
		async handler({ query }, ctx) {
			const found = await owned(ctx.request, query.stream_id);
			if ("response" in found) return found.response;
			await tx.store.deleteStream(found.stream.id);
			return new Response(null, { status: 204, headers: noStore });
		},
	});

	const readStatus = defineEndpoint({
		method: "GET",
		path: "/ssf/status",
		query: requiredStreamIdQuery,
		metadata: { ...limit(120), description: "SSF read stream status" },
		async handler({ query }, ctx) {
			const found = await owned(ctx.request, query.stream_id);
			if ("response" in found) return found.response;
			return json({
				stream_id: found.stream.id,
				status: found.stream.status,
				...(found.stream.statusReason ? { reason: found.stream.statusReason } : {}),
			});
		},
	});

	const updateStatus = defineEndpoint({
		method: "POST",
		path: "/ssf/status",
		body: z.object({
			stream_id: z.string().min(1).max(256),
			status: z.enum(["enabled", "paused", "disabled"]),
			reason: z.string().max(1024).optional(),
			subject: z.unknown().optional(),
		}),
		metadata: { ...limit(30), description: "SSF update stream status" },
		async handler({ body }, ctx) {
			const found = await owned(ctx.request, body.stream_id);
			if ("response" in found) return found.response;
			if (body.subject !== undefined) {
				return problem(501, "not_implemented", "subject level status is not supported");
			}
			await tx.setStatus(found.stream, body.status, body.reason);
			return json({
				stream_id: found.stream.id,
				status: body.status,
				...(body.reason ? { reason: body.reason } : {}),
			});
		},
	});

	const subjectBody = z.object({
		stream_id: z.string().min(1).max(256),
		subject: z.unknown(),
		verified: z.boolean().optional(),
	});

	/** In mode "all" the list holds exclusions, so add and remove swap roles. */
	function subjectEndpoint(kind: "add" | "remove") {
		return defineEndpoint({
			method: "POST",
			path: kind === "add" ? "/ssf/subjects/add" : "/ssf/subjects/remove",
			body: subjectBody,
			metadata: { ...limit(60), description: `SSF ${kind} subject` },
			async handler({ body }, ctx) {
				const found = await owned(ctx.request, body.stream_id);
				if ("response" in found) return found.response;
				const subject = parseSubject(body.subject);
				if (!subject) return problem(400, "invalid_request", "invalid subject identifier");
				const included = kind === "add";
				const listIncludes = found.stream.subjectMode === "none";
				if (included === listIncludes) {
					await tx.store.setSubject(found.stream.id, subject, body.verified !== false);
				} else {
					await tx.store.removeSubject(found.stream.id, subject);
				}
				return new Response(null, { status: 200, headers: noStore });
			},
		});
	}

	const verification = defineEndpoint({
		method: "POST",
		path: "/ssf/verify",
		body: z.object({
			stream_id: z.string().min(1).max(256),
			state: z.string().max(1024).optional(),
		}),
		metadata: { ...limit(20), description: "SSF request a verification event" },
		async handler({ body }, ctx) {
			const found = await owned(ctx.request, body.stream_id);
			if ("response" in found) return found.response;
			const result = await tx.verify(found.stream, body.state);
			if (!result.ok) {
				const status = result.code === "too_many_requests" ? 429 : 400;
				return problem(status, result.code, result.message);
			}
			return new Response(null, { status: 204, headers: noStore });
		},
	});

	const poll = defineEndpoint({
		method: "POST",
		path: "/ssf/poll/:stream_id",
		params: z.object({ stream_id: z.string().min(1).max(256) }),
		body: z
			.object({
				maxEvents: z.number().int().min(0).max(1000).optional(),
				returnImmediately: z.boolean().optional(),
				ack: z.array(z.string().max(256)).max(1000).optional(),
				setErrs: z
					.record(
						z.string().max(256),
						z.object({ err: z.string().max(128), description: z.string().max(1024).optional() }),
					)
					.optional(),
			})
			.default({}),
		metadata: { ...limit(120), description: "RFC 8936 poll for security event tokens" },
		async handler({ params, body }, ctx) {
			const found = await owned(ctx.request, params.stream_id);
			if ("response" in found) return found.response;
			if (found.stream.deliveryMethod !== DELIVERY_POLL) {
				return problem(400, "invalid_request", "stream is not a poll stream");
			}
			const result = await tx.poll(found.stream, body);
			return new Response(JSON.stringify(result), {
				status: 200,
				headers: { "Content-Type": "application/json", ...noStore },
			});
		},
	});

	return [
		wellKnown,
		createStream,
		readStream,
		patchStream,
		replaceStream,
		deleteStream,
		readStatus,
		updateStatus,
		subjectEndpoint("add"),
		subjectEndpoint("remove"),
		verification,
		poll,
	];
}
