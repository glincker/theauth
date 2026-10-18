import type {
	CreateEnrollmentTokenInput,
	DeviceDetail,
	DeviceFilters,
	DeviceFleetStats,
	DeviceRow,
	EnrollmentToken,
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
	};
}
