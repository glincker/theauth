/** Plugins the `add_plugin` tool can scaffold. Every snippet matches the real factory signature. */
export interface CatalogPlugin {
	/** Name accepted by `add_plugin`. */
	id: string;
	/** Factory exported by `importFrom`. */
	factory: string;
	importFrom: string;
	/** Extra packages to install beyond @glinr/theauth. */
	install: string[];
	/** True when the plugin throws at init unless `auth.session.secret` is configured. */
	needsSession: boolean;
	/** Source of the entry to put in the `plugins` array. */
	call: string;
	docs: string;
	summary: string;
}

export const PLUGIN_CATALOG: readonly CatalogPlugin[] = [
	{
		id: "email-password",
		factory: "emailPassword",
		importFrom: "@glinr/theauth-email",
		install: ["@glinr/theauth-email"],
		needsSession: false,
		call: `emailPassword({
      appUrl: process.env.APP_URL!,
      sendVerificationEmail: async (email, _token, url) => sendMail(email, "Verify your email", url),
      sendResetEmail: async (email, _token, url) => sendMail(email, "Reset your password", url),
    })`,
		docs: "auth/email-password",
		summary: "Sign-up, sign-in, email verification and password reset.",
	},
	{
		id: "magic-link",
		factory: "magicLink",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: true,
		call: `magicLink({
      appUrl: process.env.APP_URL!,
      sendMagicLink: async (email, _token, url) => sendMail(email, "Your sign-in link", url),
    })`,
		docs: "auth/magic-link",
		summary: "Passwordless sign-in by emailed link.",
	},
	{
		id: "email-otp",
		factory: "emailOtp",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: true,
		call: `emailOtp({
      sendOtp: async (email, code) => sendMail(email, "Your code", code),
    })`,
		docs: "auth/email-otp",
		summary: "Passwordless sign-in with a one-time code.",
	},
	{
		id: "passkey",
		factory: "passkey",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: false,
		call: `passkey({
      rpName: "My App",
      rpId: "example.com",
      origin: "https://example.com",
    })`,
		docs: "auth/passkey",
		summary: "WebAuthn passkeys.",
	},
	{
		id: "two-factor",
		factory: "twoFactor",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: false,
		call: "twoFactor()",
		docs: "auth/two-factor",
		summary: "TOTP two-factor enrollment and verification.",
	},
	{
		id: "organization",
		factory: "organization",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: false,
		call: "organization()",
		docs: "auth/organizations",
		summary: "Organizations, members, invitations and roles.",
	},
	{
		id: "api-keys",
		factory: "apiKeys",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: false,
		call: "apiKeys()",
		docs: "auth/api-keys",
		summary: "User-owned API keys, shown once.",
	},
	{
		id: "anonymous",
		factory: "anonymousAuth",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: true,
		call: "anonymousAuth()",
		docs: "auth/anonymous",
		summary: "Guest sessions that can be upgraded later.",
	},
	{
		id: "admin",
		factory: "admin",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: false,
		call: "admin()",
		docs: "auth/admin",
		summary: "User management endpoints for admins.",
	},
	{
		id: "gdpr",
		factory: "gdpr",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: false,
		call: "gdpr()",
		docs: "gdpr",
		summary: "Data export and erasure endpoints.",
	},
	{
		id: "agent-registration",
		factory: "agentRegistration",
		importFrom: "@glinr/theauth",
		install: [],
		needsSession: false,
		call: `agentRegistration({
      isAdmin: (user) => user.metadata?.role === "admin",
    })`,
		docs: "agent-registration-tokens",
		summary: "One-time tokens that let a headless agent register itself.",
	},
];

export function findPlugin(id: string): CatalogPlugin | undefined {
	return PLUGIN_CATALOG.find((p) => p.id === id);
}

export type AddPluginResult = { ok: true; text: string } | { ok: false; message: string };

/** Build the instructions an assistant applies to the user's theauth config. */
export function scaffoldPlugin(id: string, packageManager = "pnpm"): AddPluginResult {
	const plugin = findPlugin(id);
	if (!plugin) {
		const known = PLUGIN_CATALOG.map((p) => p.id).join(", ");
		return { ok: false, message: `Unknown plugin "${id}". Known plugins: ${known}.` };
	}
	const add = packageManager === "npm" ? "npm install" : `${packageManager} add`;
	const lines: string[] = [`Plugin: ${plugin.id} (${plugin.summary})`, ""];
	if (plugin.install.length > 0) {
		lines.push("1. Install:", `   ${add} ${plugin.install.join(" ")}`, "");
	}
	lines.push(
		`${plugin.install.length > 0 ? "2" : "1"}. Import:`,
		`   import { ${plugin.factory} } from "${plugin.importFrom}";`,
		"",
		`${plugin.install.length > 0 ? "3" : "2"}. Add to the plugins array of createTheAuth:`,
		"  plugins: [",
		`    ${plugin.call},`,
		"  ],",
		"",
	);
	if (plugin.needsSession) {
		lines.push(
			"This plugin throws at startup unless sessions are configured. Add to the createTheAuth config:",
			"  auth: { session: { secret: process.env.THEAUTH_SESSION_SECRET! } },",
			"and set THEAUTH_SESSION_SECRET to a random string of 32+ characters (do not commit it).",
			"",
		);
	}
	lines.push(`Docs: https://docs.theauth.dev/${plugin.docs}`);
	return { ok: true, text: lines.join("\n") };
}
