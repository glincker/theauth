import type {
	AddedDeviceCredential,
	CreateEnrollmentTokenInput,
	DeviceBundle,
	DeviceCredentialInput,
	DeviceDetail,
	DeviceFilters,
	DeviceFleetStats,
	DeviceRow,
	EnrollmentToken,
	EnrollmentTokenSummary,
} from "./device-types.js";
import type { ApiResult } from "./types.js";

type Fetcher = <T>(path: string, options?: RequestInit) => Promise<ApiResult<T>>;

export interface DeviceApi {
	getDevices: (filters?: DeviceFilters) => Promise<ApiResult<DeviceRow[]>>;
	getDevice: (id: string) => Promise<ApiResult<DeviceDetail>>;
	getDeviceStats: () => Promise<ApiResult<DeviceFleetStats>>;
	suspendDevice: (id: string, reason?: string) => Promise<ApiResult<DeviceRow>>;
	resumeDevice: (id: string) => Promise<ApiResult<DeviceRow>>;
	/** Permanent. The server cascades the device's delegations. */
	revokeDevice: (
		id: string,
		reason?: string,
	) => Promise<ApiResult<{ revokedDelegations: string[] }>>;
	createEnrollmentToken: (input: CreateEnrollmentTokenInput) => Promise<ApiResult<EnrollmentToken>>;
	/** Ids, usage and state only. The plaintext is shown once, at creation. */
	listEnrollmentTokens: () => Promise<ApiResult<EnrollmentTokenSummary[]>>;
	revokeEnrollmentToken: (id: string) => Promise<ApiResult<undefined>>;
	updateDeviceGroups: (id: string, groups: string[]) => Promise<ApiResult<DeviceRow>>;
	addDeviceCredential: (
		id: string,
		input: DeviceCredentialInput,
	) => Promise<ApiResult<AddedDeviceCredential>>;
	revokeDeviceCredential: (id: string, credentialId: string) => Promise<ApiResult<undefined>>;
	issueDeviceBundle: (id: string, ttlSeconds?: number) => Promise<ApiResult<DeviceBundle>>;
}

/** Query string for GET /devices. Only keys the route reads. */
export function deviceQuery(filters?: DeviceFilters): string {
	const params = new URLSearchParams();
	if (filters?.status) params.set("status", filters.status);
	if (filters?.group) params.set("group", filters.group);
	if (filters?.limit !== undefined) params.set("limit", String(filters.limit));
	if (filters?.offset !== undefined) params.set("offset", String(filters.offset));
	const qs = params.toString();
	return qs ? `?${qs}` : "";
}

export function createDeviceApi(fetch: Fetcher): DeviceApi {
	const id = encodeURIComponent;
	return {
		getDevices: (filters) => fetch<DeviceRow[]>(`/api/devices${deviceQuery(filters)}`),
		getDevice: (deviceId) => fetch<DeviceDetail>(`/api/devices/${id(deviceId)}`),
		getDeviceStats: () => fetch<DeviceFleetStats>("/api/devices/stats"),
		suspendDevice: (deviceId, reason) =>
			fetch<DeviceRow>(`/api/devices/${id(deviceId)}/suspend`, {
				method: "POST",
				body: JSON.stringify(reason ? { reason } : {}),
			}),
		resumeDevice: (deviceId) =>
			fetch<DeviceRow>(`/api/devices/${id(deviceId)}/resume`, { method: "POST" }),
		revokeDevice: (deviceId, reason) =>
			fetch<{ revokedDelegations: string[] }>(
				`/api/devices/${id(deviceId)}${reason ? `?reason=${encodeURIComponent(reason)}` : ""}`,
				{ method: "DELETE" },
			),
		createEnrollmentToken: (input) =>
			fetch<EnrollmentToken>("/api/devices/enrollment-tokens", {
				method: "POST",
				body: JSON.stringify(input),
			}),
		listEnrollmentTokens: () => fetch<EnrollmentTokenSummary[]>("/api/devices/enrollment-tokens"),
		revokeEnrollmentToken: (tokenId) =>
			fetch<undefined>(`/api/devices/enrollment-tokens/${id(tokenId)}`, { method: "DELETE" }),
		updateDeviceGroups: (deviceId, groups) =>
			fetch<DeviceRow>(`/api/devices/${id(deviceId)}`, {
				method: "PATCH",
				body: JSON.stringify({ groups }),
			}),
		addDeviceCredential: (deviceId, input) =>
			fetch<AddedDeviceCredential>(`/api/devices/${id(deviceId)}/credentials`, {
				method: "POST",
				body: JSON.stringify(input),
			}),
		revokeDeviceCredential: (deviceId, credentialId) =>
			fetch<undefined>(`/api/devices/${id(deviceId)}/credentials/${id(credentialId)}`, {
				method: "DELETE",
			}),
		issueDeviceBundle: (deviceId, ttlSeconds) =>
			fetch<DeviceBundle>(`/api/devices/${id(deviceId)}/bundle`, {
				method: "POST",
				body: JSON.stringify(ttlSeconds ? { ttlSeconds } : {}),
			}),
	};
}
