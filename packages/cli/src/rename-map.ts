/**
 * Single source of truth for the Kavach to TheAuth identifier rename.
 * Derived from the historical RENAME-MAP. `package` is the directory under
 * packages/ whose public entry point must export `canonical`; a test enforces it.
 */
export interface RenameEntry {
	readonly old: string;
	readonly canonical: string;
	readonly package: string;
}

export const RENAME_MAP: readonly RenameEntry[] = [
	{ old: "createKavach", canonical: "createTheAuth", package: "core" },
	{ old: "Kavach", canonical: "TheAuth", package: "core" },
	{ old: "KavachConfig", canonical: "TheAuthConfig", package: "core" },
	{ old: "KavachInstance", canonical: "TheAuthInstance", package: "core" },
	{ old: "KavachHooks", canonical: "TheAuthHooks", package: "core" },
	{ old: "KavachPlugin", canonical: "TheAuthPlugin", package: "core" },
	{ old: "KavachError", canonical: "TheAuthError", package: "core" },
	{ old: "KAVACH_AGENT_CREDENTIAL", canonical: "THEAUTH_AGENT_CREDENTIAL", package: "core" },
	{
		old: "KAVACH_PERMISSION_CREDENTIAL",
		canonical: "THEAUTH_PERMISSION_CREDENTIAL",
		package: "core",
	},
	{
		old: "KAVACH_DELEGATION_CREDENTIAL",
		canonical: "THEAUTH_DELEGATION_CREDENTIAL",
		package: "core",
	},
	{ old: "KavachApiError", canonical: "TheAuthApiError", package: "client" },
	{ old: "KavachClientOptions", canonical: "TheAuthClientOptions", package: "client" },
	{ old: "KavachClient", canonical: "TheAuthClient", package: "client" },
	{ old: "createKavachClient", canonical: "createTheAuthClient", package: "client" },
	{ old: "KavachUser", canonical: "TheAuthUser", package: "react" },
	{ old: "KavachSession", canonical: "TheAuthSession", package: "react" },
	{ old: "KavachAgent", canonical: "TheAuthAgent", package: "react" },
	{ old: "KavachPermission", canonical: "TheAuthPermission", package: "react" },
	{ old: "KavachContextValue", canonical: "TheAuthContextValue", package: "react" },
	{ old: "KavachContext", canonical: "TheAuthContext", package: "react" },
	{ old: "KavachProvider", canonical: "TheAuthProvider", package: "react" },
	{ old: "KavachProviderProps", canonical: "TheAuthProviderProps", package: "react" },
	{ old: "useKavachContext", canonical: "useTheAuthContext", package: "react" },
	{ old: "KAVACH_KEY", canonical: "THEAUTH_KEY", package: "vue" },
	{ old: "KavachPluginOptions", canonical: "TheAuthPluginOptions", package: "vue" },
	{ old: "createKavachPlugin", canonical: "createTheAuthPlugin", package: "vue" },
	{ old: "KavachUser", canonical: "TheAuthUser", package: "vue" },
	{ old: "KavachSession", canonical: "TheAuthSession", package: "vue" },
	{ old: "KavachAgent", canonical: "TheAuthAgent", package: "vue" },
	{ old: "KavachPermission", canonical: "TheAuthPermission", package: "vue" },
	{ old: "KavachContextValue", canonical: "TheAuthContextValue", package: "vue" },
	{ old: "createKavachClient", canonical: "createTheAuthClient", package: "svelte" },
	{ old: "KavachClientOptions", canonical: "TheAuthClientOptions", package: "svelte" },
	{ old: "KavachClient", canonical: "TheAuthClient", package: "svelte" },
	{ old: "KavachUser", canonical: "TheAuthUser", package: "svelte" },
	{ old: "KavachSession", canonical: "TheAuthSession", package: "svelte" },
	{ old: "KavachAgent", canonical: "TheAuthAgent", package: "svelte" },
	{ old: "KavachPermission", canonical: "TheAuthPermission", package: "svelte" },
	{ old: "KavachStorage", canonical: "TheAuthStorage", package: "expo" },
	{ old: "KavachExpoConfig", canonical: "TheAuthExpoConfig", package: "expo" },
	{ old: "KavachContextValue", canonical: "TheAuthContextValue", package: "expo" },
	{ old: "KavachExpoContext", canonical: "TheAuthExpoContext", package: "expo" },
	{ old: "KavachExpoProvider", canonical: "TheAuthExpoProvider", package: "expo" },
	{ old: "KavachExpoProviderProps", canonical: "TheAuthExpoProviderProps", package: "expo" },
	{ old: "useKavachContext", canonical: "useTheAuthContext", package: "expo" },
	{ old: "KavachUser", canonical: "TheAuthUser", package: "expo" },
	{ old: "KavachSession", canonical: "TheAuthSession", package: "expo" },
	{ old: "KavachAgent", canonical: "TheAuthAgent", package: "expo" },
	{ old: "KavachPermission", canonical: "TheAuthPermission", package: "expo" },
	{ old: "KavachSettings", canonical: "TheAuthSettings", package: "dashboard" },
	{ old: "KavachApiClient", canonical: "TheAuthApiClient", package: "dashboard" },
	{ old: "KavachDashboard", canonical: "TheAuthDashboard", package: "dashboard" },
	{ old: "KavachEmailError", canonical: "TheAuthEmailError", package: "auth/email" },
	{ old: "KavachNextjsOptions", canonical: "TheAuthNextjsOptions", package: "adapters/nextjs" },
	{ old: "KavachNextjsHandlers", canonical: "TheAuthNextjsHandlers", package: "adapters/nextjs" },
	{ old: "kavachNextjs", canonical: "theAuthNextjs", package: "adapters/nextjs" },
	{ old: "KavachNestjsOptions", canonical: "TheAuthNestjsOptions", package: "adapters/nestjs" },
	{ old: "buildKavachRouter", canonical: "buildTheAuthRouter", package: "adapters/nestjs" },
	{ old: "kavachMiddleware", canonical: "theAuthMiddleware", package: "adapters/nestjs" },
	{ old: "KavachModuleOptions", canonical: "TheAuthModuleOptions", package: "adapters/nestjs" },
	{ old: "KavachModule", canonical: "TheAuthModule", package: "adapters/nestjs" },
	{
		old: "KavachTanStackOptions",
		canonical: "TheAuthTanStackOptions",
		package: "adapters/tanstack",
	},
	{
		old: "KavachTanStackHandlers",
		canonical: "TheAuthTanStackHandlers",
		package: "adapters/tanstack",
	},
	{ old: "kavachTanStack", canonical: "theAuthTanStack", package: "adapters/tanstack" },
	{
		old: "KavachSvelteKitOptions",
		canonical: "TheAuthSvelteKitOptions",
		package: "adapters/sveltekit",
	},
	{
		old: "KavachSvelteKitHandlers",
		canonical: "TheAuthSvelteKitHandlers",
		package: "adapters/sveltekit",
	},
	{ old: "kavachSvelteKit", canonical: "theAuthSvelteKit", package: "adapters/sveltekit" },
	{ old: "KavachAstroOptions", canonical: "TheAuthAstroOptions", package: "adapters/astro" },
	{ old: "KavachAstroHandlers", canonical: "TheAuthAstroHandlers", package: "adapters/astro" },
	{ old: "kavachAstro", canonical: "theAuthAstro", package: "adapters/astro" },
	{ old: "KavachNuxtOptions", canonical: "TheAuthNuxtOptions", package: "adapters/nuxt" },
	{ old: "kavachNuxt", canonical: "theAuthNuxt", package: "adapters/nuxt" },
	{ old: "KavachFastifyOptions", canonical: "TheAuthFastifyOptions", package: "adapters/fastify" },
	{ old: "kavachFastify", canonical: "theAuthFastify", package: "adapters/fastify" },
	{
		old: "KavachSolidStartOptions",
		canonical: "TheAuthSolidStartOptions",
		package: "adapters/solidstart",
	},
	{
		old: "KavachSolidStartHandlers",
		canonical: "TheAuthSolidStartHandlers",
		package: "adapters/solidstart",
	},
	{ old: "kavachSolidStart", canonical: "theAuthSolidStart", package: "adapters/solidstart" },
	{ old: "KavachPrismaAdapter", canonical: "TheAuthPrismaAdapter", package: "adapters/prisma" },
];

/** Old env var prefix and its replacement. */
export const ENV_PREFIX_OLD = "KAVACH_";
export const ENV_PREFIX_NEW = "THEAUTH_";

const SCOPED_OLD = "@kavachos/";
const UNSCOPED_OLD = "kavachos";
const PACKAGE_SUFFIX_OVERRIDES: Readonly<Record<string, string>> = {
	discovery: "plugin-discovery",
	telemetry: "plugin-telemetry",
};

/**
 * Map an old import specifier (`kavachos`, `kavachos/x`, `@kavachos/react`) to
 * its new package path, or return null when the specifier is not an old name.
 */
export function mapImportPath(specifier: string): string | null {
	if (specifier === UNSCOPED_OLD || specifier.startsWith(`${UNSCOPED_OLD}/`)) {
		return `@glinr/theauth${specifier.slice(UNSCOPED_OLD.length)}`;
	}
	if (!specifier.startsWith(SCOPED_OLD)) return null;
	const rest = specifier.slice(SCOPED_OLD.length);
	const slash = rest.indexOf("/");
	const name = slash === -1 ? rest : rest.slice(0, slash);
	const subpath = slash === -1 ? "" : rest.slice(slash);
	if (name === "") return null;
	if (name === "core") return `@glinr/theauth${subpath}`;
	const suffix = PACKAGE_SUFFIX_OVERRIDES[name] ?? name;
	return `@glinr/theauth-${suffix}${subpath}`;
}
