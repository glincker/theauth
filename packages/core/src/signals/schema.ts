/** Drizzle schema for the Shared Signals transmitter. */

import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const ssfStreams = sqliteTable("theauth_ssf_streams", {
	id: text("id").primaryKey(),
	owner: text("owner").notNull(),
	aud: text("aud", { mode: "json" }).notNull().$type<string[]>(),
	eventsRequested: text("events_requested", { mode: "json" }).notNull().$type<string[]>(),
	eventsDelivered: text("events_delivered", { mode: "json" }).notNull().$type<string[]>(),
	deliveryMethod: text("delivery_method").notNull(),
	endpointUrl: text("endpoint_url"),
	authorizationHeader: text("authorization_header"),
	status: text("status").notNull().default("enabled"),
	statusReason: text("status_reason"),
	subjectMode: text("subject_mode").notNull().default("all"),
	description: text("description"),
	minVerificationInterval: integer("min_verification_interval"),
	lastVerifiedAt: integer("last_verified_at", { mode: "timestamp" }),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const ssfSubjects = sqliteTable("theauth_ssf_subjects", {
	id: text("id").primaryKey(),
	streamId: text("stream_id").notNull(),
	subjectKeyHash: text("subject_key_hash").notNull(),
	subject: text("subject", { mode: "json" }).notNull().$type<unknown>(),
	verified: integer("verified").notNull().default(1),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const ssfOutbox = sqliteTable("theauth_ssf_outbox", {
	jti: text("jti").primaryKey(),
	streamId: text("stream_id").notNull(),
	jwt: text("jwt").notNull(),
	status: text("status").notNull().default("pending"),
	attempts: integer("attempts").notNull().default(0),
	nextAttemptAt: integer("next_attempt_at", { mode: "timestamp" }).notNull(),
	lastError: text("last_error"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});
