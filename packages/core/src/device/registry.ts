import { and, eq, gte, isNull, sql } from "drizzle-orm";
import type { JWK } from "jose";
import { generateId, randomBytes, sha256, toBase64Url } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, deviceCredentials, devices, permissions } from "../db/schema.js";
import type { Permission } from "../types.js";
import { generateDevicePsk, normalizeDeviceJwk, normalizeX509Thumbprint } from "./credentials.js";
import type {
	Device,
	DeviceCredential,
	DeviceCredentialInput,
	DeviceFilter,
	DeviceFleetStats,
	IssuedDeviceCredential,
	RegisterDeviceInput,
} from "./types.js";

type DeviceRow = typeof devices.$inferSelect;
type CredentialRow = typeof deviceCredentials.$inferSelect;

export const nowSec = (): number => Math.floor(Date.now() / 1000);
const toDate = (sec: number | null): Date | null => (sec == null ? null : new Date(sec * 1000));
const toSec = (d: Date | undefined | null): number | null =>
	d ? Math.floor(d.getTime() / 1000) : null;

/** Thrown for caller mistakes (bad input, duplicates, caps). Routes map it to 400 or 409. */
export class DeviceInputError extends Error {
	readonly code: "INVALID_INPUT" | "CONFLICT" | "LIMIT_REACHED" | "NOT_FOUND";
	constructor(code: DeviceInputError["code"], message: string) {
		super(message);
		this.name = "DeviceInputError";
		this.code = code;
	}
}

function toPermission(row: typeof permissions.$inferSelect): Permission {
	const p: Permission = { resource: row.resource, actions: row.actions as string[] };
	if (row.constraints) p.constraints = row.constraints as Permission["constraints"];
	if (row.relation) p.relation = row.relation;
	return p;
}

export function toCredential(row: CredentialRow): DeviceCredential {
	const out: DeviceCredential = {
		id: row.id,
		deviceId: row.deviceId,
		kind: row.kind,
		lookup: row.lookup,
		status: row.status,
		expiresAt: toDate(row.expiresAt),
		lastUsedAt: toDate(row.lastUsedAt),
		createdAt: toDate(row.createdAt) ?? new Date(0),
	};
	if (row.publicJwk) out.publicJwk = row.publicJwk as JWK;
	return out;
}

export function createDeviceRegistry(db: Database, maxPerOwner: number) {
	async function permissionsOf(agentId: string): Promise<Permission[]> {
		const rows = await db.select().from(permissions).where(eq(permissions.agentId, agentId));
		return rows.map(toPermission);
	}

	async function toDevice(row: DeviceRow): Promise<Device> {
		const d: Device = {
			id: row.id,
			agentId: row.agentId,
			ownerId: row.ownerId,
			name: row.name,
			status: row.status,
			groups: row.groups ?? [],
			permissions: await permissionsOf(row.agentId),
			metadata: row.metadata ?? {},
			expiresAt: toDate(row.expiresAt),
			lastSeenAt: toDate(row.lastSeenAt),
			createdAt: toDate(row.createdAt) ?? new Date(0),
			updatedAt: toDate(row.updatedAt) ?? new Date(0),
		};
		if (row.tenantId) d.tenantId = row.tenantId;
		if (row.kind) d.kind = row.kind;
		if (row.hardwareId) d.hardwareId = row.hardwareId;
		if (row.statusReason) d.statusReason = row.statusReason;
		if (row.enrollmentId) d.enrollmentId = row.enrollmentId;
		if (row.attestation) d.attestation = row.attestation;
		if (row.lastSeenIp) d.lastSeenIp = row.lastSeenIp;
		return d;
	}

	async function getRow(id: string): Promise<DeviceRow | null> {
		const rows = await db.select().from(devices).where(eq(devices.id, id)).limit(1);
		return rows[0] ?? null;
	}

	async function get(id: string): Promise<Device | null> {
		const row = await getRow(id);
		return row ? toDevice(row) : null;
	}

	async function list(filter: DeviceFilter = {}): Promise<Device[]> {
		const conditions = [];
		if (filter.ownerId) conditions.push(eq(devices.ownerId, filter.ownerId));
		if (filter.tenantId) conditions.push(eq(devices.tenantId, filter.tenantId));
		if (filter.status) conditions.push(eq(devices.status, filter.status));
		if (filter.enrollmentId) conditions.push(eq(devices.enrollmentId, filter.enrollmentId));
		const limit = Math.min(Math.max(filter.limit ?? 100, 1), 1000);
		const rows = await db
			.select()
			.from(devices)
			.where(conditions.length > 0 ? and(...conditions) : undefined)
			.orderBy(devices.createdAt, devices.id)
			.limit(filter.group ? 1000 : limit)
			.offset(filter.offset ?? 0);
		// Groups are a JSON array; filtering in code keeps one portable query across dialects.
		const picked = filter.group
			? rows.filter((r) => (r.groups ?? []).includes(filter.group as string)).slice(0, limit)
			: rows;
		return Promise.all(picked.map(toDevice));
	}

	/** Fleet health counters: devices per status, and active devices seen in the last hour, day, or never. */
	async function stats(ownerId?: string): Promise<DeviceFleetStats> {
		const scope = ownerId ? eq(devices.ownerId, ownerId) : undefined;
		const byStatus = await db
			.select({ status: devices.status, n: sql<number>`count(*)` })
			.from(devices)
			.where(scope)
			.groupBy(devices.status);
		const out: DeviceFleetStats = {
			total: 0,
			active: 0,
			suspended: 0,
			revoked: 0,
			seenLastHour: 0,
			seenLastDay: 0,
			neverSeen: 0,
		};
		for (const row of byStatus) {
			out[row.status] = Number(row.n);
			out.total += Number(row.n);
		}
		const now = nowSec();
		const active = and(eq(devices.status, "active"), scope);
		const count = async (cond: ReturnType<typeof and>) =>
			Number(
				(await db.select({ n: sql<number>`count(*)` }).from(devices).where(and(active, cond)))[0]
					?.n ?? 0,
			);
		out.seenLastHour = await count(gte(devices.lastSeenAt, now - 3600));
		out.seenLastDay = await count(gte(devices.lastSeenAt, now - 86_400));
		out.neverSeen = await count(isNull(devices.lastSeenAt));
		return out;
	}

	async function countLive(ownerId: string): Promise<number> {
		const rows = await db
			.select({ n: sql<number>`count(*)` })
			.from(devices)
			.where(and(eq(devices.ownerId, ownerId), sql`${devices.status} <> 'revoked'`));
		return Number(rows[0]?.n ?? 0);
	}

	/** Build the row for a new credential. Throws DeviceInputError on a bad key or thumbprint. */
	async function buildCredential(
		deviceId: string,
		input: DeviceCredentialInput,
	): Promise<{ row: CredentialRow; secret?: string }> {
		const base = {
			id: generateId(),
			deviceId,
			status: "active" as const,
			expiresAt: null,
			lastUsedAt: null,
			createdAt: nowSec(),
		};
		if (input.kind === "psk") {
			const psk = await generateDevicePsk();
			return {
				row: { ...base, kind: "psk", lookup: psk.lookup, secretHash: psk.hash, publicJwk: null },
				secret: psk.secret,
			};
		}
		if (input.kind === "jwk") {
			const key = await normalizeDeviceJwk(input.jwk);
			if (!key.ok) throw new DeviceInputError("INVALID_INPUT", key.message);
			return {
				row: {
					...base,
					kind: "jwk",
					lookup: key.thumbprint,
					secretHash: null,
					publicJwk: key.jwk as Record<string, unknown>,
				},
			};
		}
		const thumbprint = normalizeX509Thumbprint(input.thumbprint);
		if (!thumbprint) {
			throw new DeviceInputError("INVALID_INPUT", "x509 thumbprint must be base64url x5t#S256");
		}
		return {
			row: { ...base, kind: "x509", lookup: thumbprint, secretHash: null, publicJwk: null },
		};
	}

	async function insertCredential(
		deviceId: string,
		input: DeviceCredentialInput,
	): Promise<IssuedDeviceCredential> {
		const built = await buildCredential(deviceId, input);
		const taken = await db
			.select({ id: deviceCredentials.id })
			.from(deviceCredentials)
			.where(
				and(
					eq(deviceCredentials.kind, built.row.kind),
					eq(deviceCredentials.lookup, built.row.lookup),
				),
			)
			.limit(1);
		if (taken.length > 0) {
			throw new DeviceInputError("CONFLICT", "This key or certificate is already registered");
		}
		await db.insert(deviceCredentials).values(built.row);
		const issued: IssuedDeviceCredential = toCredential(built.row);
		if (built.secret) issued.secret = built.secret;
		return issued;
	}

	/**
	 * Insert the backing agent, its permissions, the device row and the first credential. No transaction (D1 has none): on failure the rows written so far are removed best effort.
	 */
	async function insert(
		input: RegisterDeviceInput & { enrollmentId?: string; attestation?: Record<string, unknown> },
	): Promise<{ device: Device; credential?: IssuedDeviceCredential }> {
		if (input.hardwareId) {
			const dup = await db
				.select({ id: devices.id })
				.from(devices)
				.where(and(eq(devices.ownerId, input.ownerId), eq(devices.hardwareId, input.hardwareId)))
				.limit(1);
			if (dup.length > 0) {
				throw new DeviceInputError(
					"CONFLICT",
					"A device with this hardware id is already registered",
				);
			}
		}
		if ((await countLive(input.ownerId)) >= maxPerOwner) {
			throw new DeviceInputError(
				"LIMIT_REACHED",
				`Owner has reached the maximum of ${maxPerOwner} devices`,
			);
		}
		const id = generateId();
		const agentId = generateId();
		const now = new Date();
		const sec = toSec(now) as number;
		// The backing agent never gets a usable bearer token: the hash is of random bytes nobody keeps,
		// and the prefix can never match a `ta_` lookup.
		await db.insert(agents).values({
			id: agentId,
			ownerId: input.ownerId,
			tenantId: input.tenantId ?? null,
			name: `device:${input.name}`,
			type: "device",
			status: "active",
			tokenHash: await sha256(toBase64Url(randomBytes(32))),
			tokenPrefix: `device:${id}`,
			expiresAt: input.expiresAt ?? null,
			metadata: { deviceId: id },
			createdAt: now,
			updatedAt: now,
		});
		try {
			const perms = input.permissions ?? [];
			if (perms.length > 0) {
				await db.insert(permissions).values(
					perms.map((p) => ({
						id: generateId(),
						agentId,
						resource: p.resource,
						actions: p.actions,
						constraints: p.constraints ?? null,
						relation: p.relation ?? null,
						createdAt: now,
					})),
				);
			}
			await db.insert(devices).values({
				id,
				agentId,
				ownerId: input.ownerId,
				tenantId: input.tenantId ?? null,
				name: input.name,
				kind: input.kind ?? null,
				hardwareId: input.hardwareId ?? null,
				status: "active",
				groups: input.groups ?? [],
				metadata: input.metadata ?? {},
				enrollmentId: input.enrollmentId ?? null,
				attestation: input.attestation ?? null,
				expiresAt: toSec(input.expiresAt),
				lastSeenAt: null,
				lastSeenIp: null,
				statusReason: null,
				createdAt: sec,
				updatedAt: sec,
			});
			const credential = input.credential
				? await insertCredential(id, input.credential)
				: undefined;
			const device = await get(id);
			if (!device) throw new Error("Device disappeared after insert");
			return credential ? { device, credential } : { device };
		} catch (err) {
			await db
				.delete(devices)
				.where(eq(devices.id, id))
				.catch(() => {});
			await db
				.delete(permissions)
				.where(eq(permissions.agentId, agentId))
				.catch(() => {});
			await db
				.delete(agents)
				.where(eq(agents.id, agentId))
				.catch(() => {});
			throw err;
		}
	}

	async function setStatus(
		id: string,
		status: Device["status"],
		reason: string | null,
	): Promise<void> {
		await db
			.update(devices)
			.set({ status, statusReason: reason, updatedAt: nowSec() })
			.where(eq(devices.id, id));
	}

	async function update(
		id: string,
		patch: { name?: string; groups?: string[]; metadata?: Record<string, unknown>; kind?: string },
	): Promise<void> {
		const set: Partial<DeviceRow> = { updatedAt: nowSec() };
		if (patch.name !== undefined) set.name = patch.name;
		if (patch.groups !== undefined) set.groups = patch.groups;
		if (patch.metadata !== undefined) set.metadata = patch.metadata;
		if (patch.kind !== undefined) set.kind = patch.kind;
		await db.update(devices).set(set).where(eq(devices.id, id));
	}

	async function listCredentials(deviceId: string): Promise<DeviceCredential[]> {
		const rows = await db
			.select()
			.from(deviceCredentials)
			.where(eq(deviceCredentials.deviceId, deviceId));
		return rows.map(toCredential);
	}

	async function revokeCredential(deviceId: string, credentialId: string): Promise<boolean> {
		const rows = await db
			.select({ id: deviceCredentials.id, status: deviceCredentials.status })
			.from(deviceCredentials)
			.where(and(eq(deviceCredentials.id, credentialId), eq(deviceCredentials.deviceId, deviceId)))
			.limit(1);
		if (rows.length === 0) return false;
		await db
			.update(deviceCredentials)
			.set({ status: "revoked" })
			.where(eq(deviceCredentials.id, credentialId));
		return true;
	}

	async function findCredential(
		kind: DeviceCredential["kind"],
		lookup: string,
	): Promise<CredentialRow | null> {
		const rows = await db
			.select()
			.from(deviceCredentials)
			.where(and(eq(deviceCredentials.kind, kind), eq(deviceCredentials.lookup, lookup)))
			.limit(1);
		return rows[0] ?? null;
	}

	/** Record use. Throttled to one write a minute per device and per credential. */
	async function touch(
		row: DeviceRow,
		credentialId: string,
		ip: string | undefined,
	): Promise<void> {
		const now = nowSec();
		if (row.lastSeenAt != null && now - row.lastSeenAt < 60 && row.lastSeenIp === (ip ?? null)) {
			return;
		}
		await db
			.update(devices)
			.set({ lastSeenAt: now, lastSeenIp: ip ?? null })
			.where(eq(devices.id, row.id));
		await db
			.update(deviceCredentials)
			.set({ lastUsedAt: now })
			.where(eq(deviceCredentials.id, credentialId));
	}

	return {
		get,
		getRow,
		stats,
		list,
		insert,
		insertCredential,
		setStatus,
		update,
		listCredentials,
		revokeCredential,
		findCredential,
		touch,
		toDevice,
	};
}

export type DeviceRegistry = ReturnType<typeof createDeviceRegistry>;
