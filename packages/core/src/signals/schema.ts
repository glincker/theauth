/** Drizzle schema for the Shared Signals transmitter. */

import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { json, timestampSec } from "../db/schema/columns.js";

export const ssfStreams = sqliteTable("theauth_ssf_streams", {
	id: text("id").primaryKey(),
	owner: text("owner").notNull(),
	aud: json<string[]>("aud").notNull(),
	eventsRequested: json<string[]>("events_requested").notNull(),
	eventsDelivered: json<string[]>("events_delivered").notNull(),
	deliveryMethod: text("delivery_method").notNull(),
	endpointUrl: text("endpoint_url"),
	authorizationHeader: text("authorization_header"),
	status: text("status").notNull().default("enabled"),
	statusReason: text("status_reason"),
	subjectMode: text("subject_mode").notNull().default("all"),
	description: text("description"),
	minVerificationInterval: integer("min_verification_interval"),
	lastVerifiedAt: timestampSec("last_verified_at"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const ssfSubjects = sqliteTable("theauth_ssf_subjects", {
	id: text("id").primaryKey(),
	streamId: text("stream_id").notNull(),
	subjectKeyHash: text("subject_key_hash").notNull(),
	subject: json<unknown>("subject").notNull(),
	verified: integer("verified").notNull().default(1),
	createdAt: timestampSec("created_at").notNull(),
});

export const ssfOutbox = sqliteTable("theauth_ssf_outbox", {
	jti: text("jti").primaryKey(),
	streamId: text("stream_id").notNull(),
	jwt: text("jwt").notNull(),
	status: text("status").notNull().default("pending"),
	attempts: integer("attempts").notNull().default(0),
	nextAttemptAt: timestampSec("next_attempt_at").notNull(),
	lastError: text("last_error"),
	createdAt: timestampSec("created_at").notNull(),
});
