/**
 * Persistence for streams, subject lists and the outbox of signed SETs.
 */

import { and, asc, eq, inArray, lte } from "drizzle-orm";
import { generateId, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { ssfOutbox, ssfStreams, ssfSubjects } from "./schema.js";
import { subjectKey } from "./subjects.js";
import type {
	DeliveryMethod,
	OutboxRow,
	OutboxStatus,
	StoredStream,
	StreamStatus,
	SubjectIdentifier,
} from "./types.js";

type StreamRow = typeof ssfStreams.$inferSelect;
type OutboxDbRow = typeof ssfOutbox.$inferSelect;

function toStream(row: StreamRow): StoredStream {
	return {
		id: row.id,
		owner: row.owner,
		aud: row.aud,
		eventsRequested: row.eventsRequested,
		eventsDelivered: row.eventsDelivered,
		deliveryMethod: row.deliveryMethod as DeliveryMethod,
		endpointUrl: row.endpointUrl,
		authorizationHeader: row.authorizationHeader,
		status: row.status as StreamStatus,
		statusReason: row.statusReason,
		subjectMode: row.subjectMode === "none" ? "none" : "all",
		description: row.description,
		minVerificationInterval: row.minVerificationInterval,
		lastVerifiedAt: row.lastVerifiedAt,
		createdAt: row.createdAt,
		updatedAt: row.updatedAt,
	};
}

function toOutbox(row: OutboxDbRow): OutboxRow {
	return {
		jti: row.jti,
		streamId: row.streamId,
		jwt: row.jwt,
		status: row.status as OutboxStatus,
		attempts: row.attempts,
		nextAttemptAt: row.nextAttemptAt,
		lastError: row.lastError,
		createdAt: row.createdAt,
	};
}

export type NewStream = Omit<StoredStream, "createdAt" | "updatedAt" | "lastVerifiedAt"> & {
	lastVerifiedAt?: Date | null;
};

export interface SignalsStore {
	createStream(stream: NewStream): Promise<StoredStream>;
	getStream(id: string): Promise<StoredStream | null>;
	listStreams(owner: string): Promise<StoredStream[]>;
	/** Streams that may receive events (not disabled). */
	listActiveStreams(): Promise<StoredStream[]>;
	updateStream(id: string, patch: Partial<Omit<StoredStream, "id" | "createdAt">>): Promise<void>;
	deleteStream(id: string): Promise<void>;

	setSubject(streamId: string, subject: SubjectIdentifier, verified: boolean): Promise<void>;
	removeSubject(streamId: string, subject: SubjectIdentifier): Promise<void>;
	hasAnySubject(streamId: string, keys: string[]): Promise<boolean>;

	enqueue(row: { jti: string; streamId: string; jwt: string; nextAttemptAt: Date }): Promise<void>;
	getOutbox(jti: string): Promise<OutboxRow | null>;
	/** Pending rows of a stream, oldest first. */
	listPending(streamId: string, limit: number): Promise<OutboxRow[]>;
	/** Pending rows of any stream whose retry time has come. */
	listDue(now: Date, limit: number): Promise<OutboxRow[]>;
	updateOutbox(
		jti: string,
		patch: Partial<Pick<OutboxRow, "status" | "attempts" | "nextAttemptAt" | "lastError">>,
	): Promise<void>;
	/** Mark pending rows of this stream acked. Returns how many matched. */
	ack(streamId: string, jtis: string[]): Promise<number>;
}

async function keyHash(key: string): Promise<string> {
	return sha256(key);
}

export function createSignalsStore(db: Database): SignalsStore {
	return {
		async createStream(stream) {
			const now = new Date();
			await db.insert(ssfStreams).values({
				id: stream.id,
				owner: stream.owner,
				aud: stream.aud,
				eventsRequested: stream.eventsRequested,
				eventsDelivered: stream.eventsDelivered,
				deliveryMethod: stream.deliveryMethod,
				endpointUrl: stream.endpointUrl,
				authorizationHeader: stream.authorizationHeader,
				status: stream.status,
				statusReason: stream.statusReason,
				subjectMode: stream.subjectMode,
				description: stream.description,
				minVerificationInterval: stream.minVerificationInterval,
				lastVerifiedAt: stream.lastVerifiedAt ?? null,
				createdAt: now,
				updatedAt: now,
			});
			return {
				...stream,
				lastVerifiedAt: stream.lastVerifiedAt ?? null,
				createdAt: now,
				updatedAt: now,
			};
		},

		async getStream(id) {
			const rows = await db.select().from(ssfStreams).where(eq(ssfStreams.id, id)).limit(1);
			return rows[0] ? toStream(rows[0]) : null;
		},

		async listStreams(owner) {
			const rows = await db.select().from(ssfStreams).where(eq(ssfStreams.owner, owner));
			return rows.map(toStream);
		},

		async listActiveStreams() {
			const rows = await db.select().from(ssfStreams);
			return rows.map(toStream).filter((s) => s.status !== "disabled");
		},

		async updateStream(id, patch) {
			const { id: _id, ...rest } = patch as Partial<StoredStream>;
			await db
				.update(ssfStreams)
				.set({ ...rest, updatedAt: new Date() })
				.where(eq(ssfStreams.id, id));
		},

		async deleteStream(id) {
			await db.delete(ssfSubjects).where(eq(ssfSubjects.streamId, id));
			await db.delete(ssfOutbox).where(eq(ssfOutbox.streamId, id));
			await db.delete(ssfStreams).where(eq(ssfStreams.id, id));
		},

		async setSubject(streamId, subject, verified) {
			const hash = await keyHash(subjectKey(subject));
			const existing = await db
				.select()
				.from(ssfSubjects)
				.where(and(eq(ssfSubjects.streamId, streamId), eq(ssfSubjects.subjectKeyHash, hash)))
				.limit(1);
			if (existing[0]) {
				await db
					.update(ssfSubjects)
					.set({ verified: verified ? 1 : 0 })
					.where(eq(ssfSubjects.id, existing[0].id));
				return;
			}
			await db.insert(ssfSubjects).values({
				id: generateId(),
				streamId,
				subjectKeyHash: hash,
				subject,
				verified: verified ? 1 : 0,
				createdAt: new Date(),
			});
		},

		async removeSubject(streamId, subject) {
			const hash = await keyHash(subjectKey(subject));
			await db
				.delete(ssfSubjects)
				.where(and(eq(ssfSubjects.streamId, streamId), eq(ssfSubjects.subjectKeyHash, hash)));
		},

		async hasAnySubject(streamId, keys) {
			if (keys.length === 0) return false;
			const hashes = await Promise.all(keys.map(keyHash));
			const rows = await db
				.select()
				.from(ssfSubjects)
				.where(and(eq(ssfSubjects.streamId, streamId), inArray(ssfSubjects.subjectKeyHash, hashes)))
				.limit(1);
			return rows.length > 0;
		},

		async enqueue(row) {
			await db.insert(ssfOutbox).values({
				jti: row.jti,
				streamId: row.streamId,
				jwt: row.jwt,
				status: "pending",
				attempts: 0,
				nextAttemptAt: row.nextAttemptAt,
				lastError: null,
				createdAt: new Date(),
			});
		},

		async getOutbox(jti) {
			const rows = await db.select().from(ssfOutbox).where(eq(ssfOutbox.jti, jti)).limit(1);
			return rows[0] ? toOutbox(rows[0]) : null;
		},

		async listPending(streamId, limit) {
			const rows = await db
				.select()
				.from(ssfOutbox)
				.where(and(eq(ssfOutbox.streamId, streamId), eq(ssfOutbox.status, "pending")))
				.orderBy(asc(ssfOutbox.createdAt))
				.limit(limit);
			return rows.map(toOutbox);
		},

		async listDue(now, limit) {
			const rows = await db
				.select()
				.from(ssfOutbox)
				.where(and(eq(ssfOutbox.status, "pending"), lte(ssfOutbox.nextAttemptAt, now)))
				.orderBy(asc(ssfOutbox.createdAt))
				.limit(limit);
			return rows.map(toOutbox);
		},

		async updateOutbox(jti, patch) {
			await db.update(ssfOutbox).set(patch).where(eq(ssfOutbox.jti, jti));
		},

		async ack(streamId, jtis) {
			if (jtis.length === 0) return 0;
			const rows = await db
				.select()
				.from(ssfOutbox)
				.where(and(eq(ssfOutbox.streamId, streamId), inArray(ssfOutbox.jti, jtis)));
			const matched = rows.filter((r) => r.status === "pending").map((r) => r.jti);
			if (matched.length > 0) {
				await db
					.update(ssfOutbox)
					.set({ status: "acked" })
					.where(and(eq(ssfOutbox.streamId, streamId), inArray(ssfOutbox.jti, matched)));
			}
			return rows.length;
		},
	};
}
