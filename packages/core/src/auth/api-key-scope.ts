/**
 * Scoping for self service API keys.
 *
 * A signed in user must not mint a key that is stronger than the user is. The caller's own grants come from the
 * `grantablePermissions` resolver. Without a resolver the grants are unknown, so a self service request may only ask
 * for an empty permission list (fail closed). Trusted server code that calls `create()` directly is not capped, and
 * an `adminOverride` predicate can lift the cap for named users.
 *
 * When the org module is configured and no resolver is given, the caller's grants default to what their org roles
 * allow (`canGrant`, built by `orgPermissionCheck` over `org.hasPermission`). With neither, the cap stays closed.
 */

export interface ApiKeyScopeConfig {
	/**
	 * Returns the permissions the user holds. A self service key can only carry permissions covered by this list.
	 * `*` covers everything, `ns:*` covers `ns:` followed by anything. Without it, self service creation accepts an
	 * empty permission list only.
	 */
	grantablePermissions?: (userId: string) => readonly string[] | Promise<readonly string[]>;
	/**
	 * Per permission check used when `grantablePermissions` is not set. Set by the core wiring from the org module,
	 * not meant to be passed by hand. Returns true when the user holds `permission` in any org they belong to.
	 */
	canGrant?: (userId: string, permission: string) => boolean | Promise<boolean>;
	/** Return true for users who may mint keys with any permission, for example platform admins. */
	adminOverride?: (userId: string) => boolean | Promise<boolean>;
}

/** True when `granted` (an exact permission or a `*` pattern) covers `requested`. */
export function permissionCovers(granted: string, requested: string): boolean {
	if (granted === "*" || granted === requested) return true;
	if (!granted.endsWith(":*")) return false;
	const base = granted.slice(0, -1); // keeps the trailing colon
	if (requested.endsWith(":*")) {
		return requested.startsWith(base) || requested === granted;
	}
	return requested.startsWith(base);
}

export type ScopeCheck = { ok: true } | { ok: false; denied: string[] };

/** Check a self service request against the caller's grants. */
export async function checkKeyPermissions(
	userId: string,
	requested: readonly string[],
	config: ApiKeyScopeConfig,
): Promise<ScopeCheck> {
	if (requested.length === 0) return { ok: true };
	if (config.adminOverride && (await config.adminOverride(userId)) === true) return { ok: true };
	if (!config.grantablePermissions && config.canGrant) {
		const denied: string[] = [];
		for (const p of requested) {
			let allowed = false;
			try {
				allowed = (await config.canGrant(userId, p)) === true;
			} catch {
				allowed = false; // fail closed when the org lookup breaks
			}
			if (!allowed) denied.push(p);
		}
		return denied.length === 0 ? { ok: true } : { ok: false, denied };
	}
	const grants = config.grantablePermissions ? await config.grantablePermissions(userId) : [];
	const denied = requested.filter((p) => !grants.some((g) => permissionCovers(g, p)));
	return denied.length === 0 ? { ok: true } : { ok: false, denied };
}

/** The slice of the org module the default scope check needs. */
export interface OrgPermissionSource {
	list: (userId: string) => Promise<Array<{ id: string }>>;
	hasPermission: (orgId: string, userId: string, permission: string) => Promise<boolean>;
}

/**
 * Default `canGrant`: the user may grant a permission when `org.hasPermission` says yes in at least one org they
 * belong to. A user with no org membership holds nothing, so the check fails closed.
 */
export function orgPermissionCheck(
	org: OrgPermissionSource,
): NonNullable<ApiKeyScopeConfig["canGrant"]> {
	return async (userId, permission) => {
		const orgs = await org.list(userId);
		for (const o of orgs) {
			if (await org.hasPermission(o.id, userId, permission)) return true;
		}
		return false;
	};
}

/** Parse an untrusted `permissions` value: an array of non empty strings, else null. */
export function parsePermissionList(value: unknown): string[] | null {
	if (!Array.isArray(value)) return null;
	if (!value.every((p) => typeof p === "string" && p.length > 0)) return null;
	return value as string[];
}
