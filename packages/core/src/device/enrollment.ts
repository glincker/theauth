import { desc, eq } from "drizzle-orm";
import { generateId, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { deviceEnrollments } from "../db/schema.js";
import { singleUseFor } from "../db/store/for-database.js";
import type { SecondaryStorage } from "../storage/types.js";
import { normalizeDeviceJwk, normalizeX509Thumbprint } from "./credentials.js";
import type { DeviceRegistry } from "./registry.js";
import { DeviceInputError, nowSec } from "./registry.js";
import {
	canonicalEnrollmentToken,
	DEFAULT_BULK_TTL_SECONDS,
	DEFAULT_CLAIM_TTL_SECONDS,
	generateBulkToken,
	generateClaimCode,
	hashEnrollmentToken,
	MAX_BULK_USES,
	MAX_ENROLLMENT_TTL_SECONDS,
} from "./tokens.js";
import type {
	CreateEnrollmentTokenInput,
	DeviceConfig,
	EnrollDeviceInput,
	EnrolledDevice,
	EnrollmentToken,
	EnrollmentTokenFilter,
	EnrollmentTokenSummary,
} from "./types.js";

const NONCE_TTL_SECONDS = 300;

/** Why an enrollment was refused. One generic message for token problems, so a caller cannot tell a wrong code from a spent one. */
export class DeviceEnrollmentError extends Error {
	readonly code: "invalid_token" | "attestation_required" | "attestation_failed" | "nonce_invalid";
	constructor(code: DeviceEnrollmentError["code"], message: string) {
		super(message);
		this.name = "DeviceEnrollmentError";
		this.code = code;
	}
}

interface EnrollmentDeps {
	db: Database;
	registry: DeviceRegistry;
	storage: SecondaryStorage;
	config: DeviceConfig;
	/** Runs the `beforeAgentCreate` policy on the device's backing agent. */
	guard: (
		ownerId: string,
		tenantId: string | undefined,
		name: string,
		perms: EnrollDeviceTemplate,
	) => Promise<void>;
}

type EnrollDeviceTemplate = CreateEnrollmentTokenInput["permissions"];

export function createDeviceEnrollment(deps: EnrollmentDeps) {
	const { db, registry, storage, config } = deps;

	async function createToken(input: CreateEnrollmentTokenInput): Promise<EnrollmentToken> {
		const isClaim = input.kind === "claim";
		const maxUses = isClaim ? 1 : input.maxUses;
		if (!maxUses || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > MAX_BULK_USES) {
			throw new DeviceInputError(
				"INVALID_INPUT",
				`bulk tokens need maxUses between 1 and ${MAX_BULK_USES}`,
			);
		}
		const ttl =
			input.ttlSeconds ?? (isClaim ? DEFAULT_CLAIM_TTL_SECONDS : DEFAULT_BULK_TTL_SECONDS);
		if (!Number.isInteger(ttl) || ttl < 60 || ttl > MAX_ENROLLMENT_TTL_SECONDS) {
			throw new DeviceInputError(
				"INVALID_INPUT",
				`ttlSeconds must be between 60 and ${MAX_ENROLLMENT_TTL_SECONDS}`,
			);
		}
		// Template permissions pass the same policy a direct registration would.
		await deps.guard(input.ownerId, input.tenantId, "enrollment-template", input.permissions ?? []);
		const token = isClaim ? generateClaimCode() : generateBulkToken();
		const canonical = canonicalEnrollmentToken(token) as string;
		const id = generateId();
		const now = nowSec();
		await db.insert(deviceEnrollments).values({
			id,
			kind: input.kind,
			tokenHash: await hashEnrollmentToken(canonical),
			ownerId: input.ownerId,
			tenantId: input.tenantId ?? null,
			template: {
				permissions: input.permissions ?? [],
				groups: input.groups ?? [],
				...(input.deviceKind !== undefined && { kind: input.deviceKind }),
				...(input.deviceTtlSeconds !== undefined && { deviceTtlSeconds: input.deviceTtlSeconds }),
			},
			maxUses,
			uses: 0,
			expiresAt: now + ttl,
			revokedAt: null,
			createdAt: now,
		});
		return {
			id,
			kind: input.kind,
			token,
			ownerId: input.ownerId,
			maxUses,
			expiresAt: new Date((now + ttl) * 1000),
		};
	}

	async function getToken(id: string) {
		const rows = await db
			.select()
			.from(deviceEnrollments)
			.where(eq(deviceEnrollments.id, id))
			.limit(1);
		return rows[0] ?? null;
	}

	async function revokeToken(id: string): Promise<boolean> {
		return singleUseFor(db).deviceEnrollments.revoke(id, nowSec());
	}

	/** Token rows for an operator view. The plaintext and the hash are never returned, only ids, usage and state. */
	async function listTokens(filter: EnrollmentTokenFilter = {}): Promise<EnrollmentTokenSummary[]> {
		const limit = Math.min(Math.max(filter.limit ?? 100, 1), 1000);
		const rows = await db
			.select()
			.from(deviceEnrollments)
			.where(filter.ownerId ? eq(deviceEnrollments.ownerId, filter.ownerId) : undefined)
			.orderBy(desc(deviceEnrollments.createdAt), desc(deviceEnrollments.id))
			.limit(limit)
			.offset(Math.max(filter.offset ?? 0, 0));
		const now = nowSec();
		return rows.map((row) => ({
			id: row.id,
			kind: row.kind,
			ownerId: row.ownerId,
			maxUses: row.maxUses,
			uses: row.uses,
			groups: row.template.groups,
			...(row.template.kind !== undefined && { deviceKind: row.template.kind }),
			status:
				row.revokedAt !== null
					? "revoked"
					: row.expiresAt <= now
						? "expired"
						: row.uses >= row.maxUses
							? "used_up"
							: "active",
			expiresAt: new Date(row.expiresAt * 1000),
			createdAt: new Date(row.createdAt * 1000),
			...(row.revokedAt !== null && { revokedAt: new Date(row.revokedAt * 1000) }),
		}));
	}

	/** Single use nonce for attestation evidence freshness (RFC 9334 section 10). */
	async function attestationNonce(): Promise<{ nonce: string; expiresAt: Date }> {
		const nonce = generateId().replace(/-/g, "") + generateId().replace(/-/g, "");
		await storage.set(`nonce:${await sha256(nonce)}`, "1", NONCE_TTL_SECONDS);
		return { nonce, expiresAt: new Date(Date.now() + NONCE_TTL_SECONDS * 1000) };
	}

	async function spendNonce(nonce: string): Promise<boolean> {
		const key = `nonce:${await sha256(nonce)}`;
		if ((await storage.get(key)) === null) return false;
		// Count spends so two concurrent enrollments with one nonce cannot both pass.
		const spent = await storage.incr(`spent:${key}`, NONCE_TTL_SECONDS);
		await storage.delete(key);
		return spent.count === 1;
	}

	async function checkAttestation(
		input: EnrollDeviceInput,
		enrollmentId: string,
		keyThumbprint?: string,
	): Promise<Record<string, unknown> | undefined> {
		const att = config.attestation;
		if (input.evidence === undefined) {
			if (att?.required) {
				throw new DeviceEnrollmentError("attestation_required", "Attestation evidence is required");
			}
			return undefined;
		}
		if (!att?.verify) {
			throw new DeviceEnrollmentError(
				"attestation_failed",
				"No attestation verifier is configured",
			);
		}
		// Evidence without a nonce cannot be shown fresh (RFC 9334 section 10), so it is refused unless the verifier opted out.
		if (input.nonce === undefined && att.requireNonce !== false) {
			throw new DeviceEnrollmentError("nonce_invalid", "Attestation evidence needs a nonce");
		}
		if (input.nonce !== undefined && !(await spendNonce(input.nonce))) {
			throw new DeviceEnrollmentError(
				"nonce_invalid",
				"Attestation nonce is unknown, expired or used",
			);
		}
		let result: Awaited<ReturnType<NonNullable<typeof att.verify>>>;
		try {
			result = await att.verify({
				evidence: input.evidence,
				enrollmentId,
				credentialKind: input.credential.kind,
				...(keyThumbprint !== undefined && { credentialKeyThumbprint: keyThumbprint }),
				...(input.nonce !== undefined && { nonce: input.nonce }),
				...(input.hardwareId !== undefined && { hardwareId: input.hardwareId }),
			});
		} catch {
			// A throwing verifier fails closed.
			throw new DeviceEnrollmentError("attestation_failed", "Attestation verifier failed");
		}
		if (!result.ok) throw new DeviceEnrollmentError("attestation_failed", result.reason);
		return result.claims ?? {};
	}

	/** Rejects a bad credential before a use is spent. Returns the key thumbprint for `jwk` credentials. */
	async function precheckCredential(input: EnrollDeviceInput): Promise<string | undefined> {
		const c = input.credential;
		if (c.kind === "jwk") {
			const key = await normalizeDeviceJwk(c.jwk);
			if (!key.ok) throw new DeviceInputError("INVALID_INPUT", key.message);
			return key.thumbprint;
		} else if (c.kind === "x509" && !normalizeX509Thumbprint(c.thumbprint)) {
			throw new DeviceInputError("INVALID_INPUT", "x509 thumbprint must be base64url x5t#S256");
		}
		return undefined;
	}

	/**
	 * Enroll a device with a claim code or bulk token. The token, attestation and credential are all checked before a use is claimed; the use is claimed with one conditional UPDATE so the last use cannot be spent twice. If the insert then fails the use is not given back (fail safe: a burned use is better than an extra device).
	 */
	async function enroll(input: EnrollDeviceInput): Promise<EnrolledDevice> {
		const invalid = () =>
			new DeviceEnrollmentError("invalid_token", "Enrollment token is invalid, expired or used up");
		const canonical = canonicalEnrollmentToken(input.token);
		if (!canonical) throw invalid();
		const hash = await hashEnrollmentToken(canonical);
		const rows = await db
			.select()
			.from(deviceEnrollments)
			.where(eq(deviceEnrollments.tokenHash, hash))
			.limit(1);
		const row = rows[0];
		const now = nowSec();
		if (!row || row.revokedAt != null || row.expiresAt <= now || row.uses >= row.maxUses)
			throw invalid();

		const keyThumbprint = await precheckCredential(input);
		const attestation = await checkAttestation(input, row.id, keyThumbprint);

		if (!(await singleUseFor(db).deviceEnrollments.spendUse(row.id, now))) throw invalid();

		const ttl = row.template.deviceTtlSeconds;
		const created = await registry.insert({
			ownerId: row.ownerId,
			...(row.tenantId && { tenantId: row.tenantId }),
			name: input.name,
			...(row.template.kind !== undefined && { kind: row.template.kind }),
			...(input.hardwareId !== undefined && { hardwareId: input.hardwareId }),
			groups: row.template.groups,
			permissions: row.template.permissions,
			...(input.metadata !== undefined && { metadata: input.metadata }),
			...(ttl !== undefined && { expiresAt: new Date((now + ttl) * 1000) }),
			credential: input.credential,
			enrollmentId: row.id,
			...(attestation !== undefined && { attestation }),
		});
		if (!created.credential) throw new Error("Enrollment created no credential");
		return { device: created.device, credential: created.credential };
	}

	return { createToken, listTokens, getToken, revokeToken, attestationNonce, enroll };
}
