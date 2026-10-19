import { clampBundleTtl } from "./bundle.js";
import type { DeviceRegistry } from "./registry.js";
import { DeviceInputError } from "./registry.js";
import { DEFAULT_REVOCATION_MAX_ENTRIES } from "./revocation.js";

const PAGE = 1000;

/** Snapshot lifetime: the configured value, else the bundle TTL, with the bundle's floor and cap. */
export function clampRevocationTtl(
	configured: number | undefined,
	bundleTtl: number | undefined,
): number {
	return clampBundleTtl(configured, bundleTtl);
}

/**
 * Ids of every revoked or suspended device of one owner. Throws instead of returning a partial list: a snapshot that silently dropped entries would let revoked devices through.
 */
export async function collectBlockedIds(
	registry: DeviceRegistry,
	ownerId: string,
	maxEntries = DEFAULT_REVOCATION_MAX_ENTRIES,
): Promise<string[]> {
	const ids: string[] = [];
	for (const status of ["revoked", "suspended"] as const) {
		for (let offset = 0; ; offset += PAGE) {
			const page = await registry.list({ ownerId, status, limit: PAGE, offset });
			for (const d of page) ids.push(d.id);
			if (ids.length > maxEntries) {
				throw new DeviceInputError(
					"INVALID_INPUT",
					`More than ${maxEntries} blocked devices for this owner; raise devices.revocations.maxEntries`,
				);
			}
			if (page.length < PAGE) break;
		}
	}
	return ids;
}
