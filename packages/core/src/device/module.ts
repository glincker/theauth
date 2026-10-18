import { recordAuditEvent } from "../audit/record.js";
import { stripReservedAuditKeys } from "../audit/reserved.js";
import type { PipelineAuthorizeOptions } from "../authorize/pipeline.js";
import type { Database } from "../db/database.js";
import type { DecisionCode } from "../permission/codes.js";
import { DECISION_CODES } from "../permission/codes.js";
import type { DenialExtra } from "../permission/engine.js";
import type { SecondaryStorage } from "../storage/types.js";
import type {
	AgentIdentity,
	AuthorizeRequest,
	AuthorizeResult,
	CreateAgentInput,
	DelegateInput,
	DelegationChain,
	Permission,
	RequestContext,
	UpdateAgentInput,
} from "../types.js";
import { clampBundleTtl, deviceBundleJwks, signDeviceBundle } from "./bundle.js";
import { createDeviceAuthenticator } from "./device-auth.js";
import { createDeviceEnrollment } from "./enrollment.js";
import { createDeviceRegistry, DeviceInputError } from "./registry.js";
import { deviceBlock, devicePrincipal } from "./state.js";
import type {
	CreateEnrollmentTokenInput,
	Device,
	DeviceConfig,
	DeviceCredentialInput,
	IssuedDeviceBundle,
	RegisterDeviceInput,
} from "./types.js";

export interface DeviceModuleDeps {
	db: Database;
	config: DeviceConfig;
	storage: SecondaryStorage;
	agent: {
		update(agentId: string, input: UpdateAgentInput): Promise<AgentIdentity>;
		revoke(agentId: string): Promise<{ revokedDelegations: string[] }>;
	};
	delegate(input: DelegateInput): Promise<DelegationChain>;
	getEffectivePermissions(agentId: string): Promise<Permission[]>;
	authorize(
		agentId: string,
		request: AuthorizeRequest,
		context?: RequestContext,
		options?: PipelineAuthorizeOptions,
	): Promise<AuthorizeResult>;
	recordDenial(
		target: { agentId: string; ownerId: string },
		request: AuthorizeRequest,
		code: DecisionCode,
		extra?: DenialExtra,
	): Promise<string>;
	guardAgentCreate(input: CreateAgentInput): Promise<void>;
}

/** IoT devices as principals. See docs/iot-devices.mdx and docs-local/design/iot-device-identity.md. */
export function createDeviceModule(deps: DeviceModuleDeps) {
	const { db, config } = deps;
	const registry = createDeviceRegistry(db, config.maxPerOwner ?? 10_000);

	async function guard(
		ownerId: string,
		tenantId: string | undefined,
		name: string,
		permissions: Permission[],
	) {
		await deps.guardAgentCreate({
			ownerId,
			...(tenantId !== undefined && { tenantId }),
			name: `device:${name}`,
			type: "device",
			permissions,
		});
	}

	const enrollment = createDeviceEnrollment({
		db,
		registry,
		storage: deps.storage,
		config,
		guard: (ownerId, tenantId, name, perms) => guard(ownerId, tenantId, name, perms ?? []),
	});
	const authenticator = createDeviceAuthenticator({ registry, storage: deps.storage, config });

	async function lifecycle(
		device: Device,
		action: string,
		parameters: Record<string, unknown> = {},
	) {
		await recordAuditEvent(db, {
			agentId: device.agentId,
			userId: device.ownerId,
			action,
			resource: `device:${device.id}`,
			result: "allowed",
			parameters: { ...parameters, ...devicePrincipal(device.id) },
		}).catch(() => {});
	}

	async function mustGet(id: string): Promise<Device> {
		const device = await registry.get(id);
		if (!device) throw new DeviceInputError("NOT_FOUND", `Device "${id}" not found`);
		return device;
	}

	async function register(input: RegisterDeviceInput) {
		await guard(input.ownerId, input.tenantId, input.name, input.permissions ?? []);
		const created = await registry.insert(input);
		await lifecycle(created.device, "device.register", {
			credential: input.credential?.kind ?? null,
		});
		return created;
	}

	async function update(
		id: string,
		patch: {
			name?: string;
			kind?: string;
			groups?: string[];
			metadata?: Record<string, unknown>;
			permissions?: Permission[];
		},
	): Promise<Device> {
		const device = await mustGet(id);
		if (device.status === "revoked") throw new DeviceInputError("CONFLICT", "Device is revoked");
		// The agent facade runs the beforeAgentCreate policy on the new permission set.
		if (patch.permissions !== undefined) {
			await deps.agent.update(device.agentId, { permissions: patch.permissions });
		}
		await registry.update(id, patch);
		return mustGet(id);
	}

	async function suspend(id: string, reason?: string): Promise<Device> {
		const device = await mustGet(id);
		if (device.status === "revoked") throw new DeviceInputError("CONFLICT", "Device is revoked");
		await registry.setStatus(id, "suspended", reason ?? null);
		await lifecycle(device, "device.suspend", { reason: reason ?? null });
		return mustGet(id);
	}

	async function resume(id: string): Promise<Device> {
		const device = await mustGet(id);
		if (device.status === "revoked")
			throw new DeviceInputError("CONFLICT", "A revoked device cannot be resumed");
		await registry.setStatus(id, "active", null);
		await lifecycle(device, "device.resume");
		return mustGet(id);
	}

	/** Permanent. Revokes the backing agent too, which pushes the revocation on the bus and cascades delegation chains. */
	async function revoke(id: string, reason?: string): Promise<{ revokedDelegations: string[] }> {
		const device = await mustGet(id);
		await registry.setStatus(id, "revoked", reason ?? null);
		const result = await deps.agent.revoke(device.agentId);
		await lifecycle(device, "device.revoke", {
			reason: reason ?? null,
			revokedDelegations: result.revokedDelegations,
		});
		return result;
	}

	async function addCredential(id: string, input: DeviceCredentialInput) {
		const device = await mustGet(id);
		if (device.status === "revoked") throw new DeviceInputError("CONFLICT", "Device is revoked");
		const credential = await registry.insertCredential(id, input);
		await lifecycle(device, "device.credential.add", {
			credentialId: credential.id,
			kind: credential.kind,
		});
		return credential;
	}

	async function revokeCredential(id: string, credentialId: string): Promise<boolean> {
		const device = await mustGet(id);
		const done = await registry.revokeCredential(id, credentialId);
		if (done) await lifecycle(device, "device.credential.revoke", { credentialId });
		return done;
	}

	async function createEnrollmentToken(input: CreateEnrollmentTokenInput) {
		return enrollment.createToken(input);
	}

	async function enroll(input: Parameters<typeof enrollment.enroll>[0]) {
		const enrolled = await enrollment.enroll(input);
		await lifecycle(enrolled.device, "device.enroll", {
			enrollmentId: enrolled.device.enrollmentId ?? null,
			attested: enrolled.device.attestation !== undefined,
		});
		return enrolled;
	}

	/**
	 * Decide whether a device may perform an action. Device level state is checked first (suspended, revoked, expired), then the full agent pipeline runs for the backing agent: hooks, own and delegated permissions, constraints, approvals, audit.
	 */
	async function authorize(
		deviceId: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
		const device = await registry.get(deviceId);
		if (!device) {
			return {
				allowed: false,
				reason: `Device "${deviceId}" not found`,
				auditId: "",
				code: DECISION_CODES.DEVICE_NOT_FOUND,
			};
		}
		const blocked = deviceBlock(device);
		if (blocked) {
			const auditId = await deps.recordDenial(
				{ agentId: device.agentId, ownerId: device.ownerId },
				context ? { ...request, context } : request,
				blocked,
				{
					parameters: {
						...(stripReservedAuditKeys(request.arguments) ?? {}),
						...devicePrincipal(device.id),
					},
				},
			);
			return {
				allowed: false,
				reason: `Device "${device.name}" is ${blocked.replace("device_", "")}`,
				auditId,
				code: blocked,
			};
		}
		return deps.authorize(device.agentId, request, context, {
			auditParameters: devicePrincipal(device.id),
		});
	}

	/** Delegate from an agent to a device. Same subset rule, depth limit and cascade as agent to agent delegation. */
	async function delegate(
		input: Omit<DelegateInput, "toAgent"> & { deviceId: string },
	): Promise<DelegationChain> {
		const device = await mustGet(input.deviceId);
		if (deviceBlock(device)) throw new DeviceInputError("CONFLICT", `Device is ${device.status}`);
		const { deviceId: _deviceId, ...rest } = input;
		return deps.delegate({ ...rest, toAgent: device.agentId });
	}

	/** Sign an offline policy bundle with the device's own and delegated permissions. */
	async function issueBundle(
		deviceId: string,
		options: { ttlSeconds?: number } = {},
	): Promise<IssuedDeviceBundle> {
		if (!config.bundleSigning) {
			throw new DeviceInputError("INVALID_INPUT", "devices.bundleSigning is not configured");
		}
		const device = await mustGet(deviceId);
		const blocked = deviceBlock(device);
		if (blocked)
			throw new DeviceInputError("CONFLICT", `Device is ${blocked.replace("device_", "")}`);
		const delegated = await deps.getEffectivePermissions(device.agentId);
		let ttl = clampBundleTtl(options.ttlSeconds, config.bundleTtlSeconds);
		// Never outlive the device itself.
		if (device.expiresAt)
			ttl = Math.min(
				ttl,
				Math.max(60, Math.floor((device.expiresAt.getTime() - Date.now()) / 1000)),
			);
		const bundle = await signDeviceBundle({
			signing: config.bundleSigning,
			issuer: config.issuer ?? "theauth",
			deviceId: device.id,
			ownerId: device.ownerId,
			groups: device.groups,
			permissions: [...device.permissions, ...delegated].filter((p) => !p.relation),
			ttlSeconds: ttl,
		});
		await lifecycle(device, "device.bundle.issue", {
			jti: bundle.claims.jti,
			exp: bundle.claims.exp,
		});
		return bundle;
	}

	return {
		register,
		get: registry.get,
		list: registry.list,
		stats: registry.stats,
		update,
		suspend,
		resume,
		revoke,
		addCredential,
		revokeCredential,
		listCredentials: registry.listCredentials,
		createEnrollmentToken,
		revokeEnrollmentToken: enrollment.revokeToken,
		getEnrollmentToken: enrollment.getToken,
		attestationNonce: enrollment.attestationNonce,
		enroll,
		authenticate: authenticator.authenticate,
		authenticateRequest: authenticator.authenticateRequest,
		authorize,
		delegate,
		issueBundle,
		jwks: () => deviceBundleJwks(config.bundleSigning),
	};
}

export type DeviceModule = ReturnType<typeof createDeviceModule>;
