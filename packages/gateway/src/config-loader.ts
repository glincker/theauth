import { readFileSync } from "node:fs";
import { z } from "zod";

// ─── JSON Config Schema ───────────────────────────────────────────────────────

const RateLimitConfigSchema = z.object({
	windowMs: z.number().int().positive(),
	max: z.number().int().positive(),
});

const CorsConfigSchema = z.object({
	origins: z.union([z.string(), z.array(z.string())]).optional(),
	methods: z.array(z.string()).optional(),
	headers: z.array(z.string()).optional(),
	maxAge: z.number().int().positive().optional(),
	credentials: z.boolean().optional(),
});

const GatewayPolicySchema = z.object({
	path: z.string().min(1),
	method: z.union([z.string(), z.array(z.string())]).optional(),
	requireAuth: z.boolean().optional(),
	requiredPermissions: z
		.array(
			z.object({
				resource: z.string().min(1),
				actions: z.array(z.string().min(1)).min(1),
			}),
		)
		.optional(),
	rateLimit: RateLimitConfigSchema.optional(),
	public: z.boolean().optional(),
});

/** RFC 9110 header field name token. */
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

/**
 * How the gateway finds the client IP. Strict so a typo cannot silently leave
 * the gateway in trust nothing mode.
 */
const TrustedProxyConfigSchema = z
	.object({
		trustedProxyCount: z.number().int().nonnegative().optional(),
		trustedHeader: z
			.string()
			.trim()
			.min(1, "must not be empty")
			.regex(HEADER_NAME, "must be a valid HTTP header name")
			.transform((v) => v.toLowerCase())
			.optional(),
	})
	.strict();

export const GatewayFileConfigSchema = z.object({
	upstream: z.string().url(),
	basePath: z.string().optional(),
	policies: z.array(GatewayPolicySchema).optional(),
	cors: CorsConfigSchema.optional(),
	rateLimit: RateLimitConfigSchema.optional(),
	audit: z.boolean().optional(),
	stripAuthHeader: z.boolean().optional(),
	trustedProxy: TrustedProxyConfigSchema.optional(),
});

export type GatewayFileConfig = z.infer<typeof GatewayFileConfigSchema>;

/**
 * Load and validate a gateway JSON config file.
 * Throws a descriptive error if the file is missing or invalid.
 */
export function loadConfigFile(path: string): GatewayFileConfig {
	let raw: string;
	try {
		raw = readFileSync(path, "utf-8");
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new Error(`Cannot read gateway config file "${path}": ${message}`);
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new Error(`Gateway config file "${path}" is not valid JSON`);
	}

	const result = GatewayFileConfigSchema.safeParse(parsed);
	if (!result.success) {
		const issues = result.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n");
		throw new Error(`Gateway config file "${path}" is invalid:\n${issues}`);
	}

	return result.data;
}

export type TrustedProxyFileConfig = z.infer<typeof TrustedProxyConfigSchema>;

/**
 * Merge the trusted proxy settings from the config file with CLI flag values
 * (flags win per key). Returns undefined when neither source sets anything,
 * which keeps the gateway in trust nothing mode. Throws on invalid flag values.
 */
export function resolveTrustedProxy(
	fileValue: TrustedProxyFileConfig | undefined,
	flags: { count?: string; header?: string } = {},
): TrustedProxyFileConfig | undefined {
	const merged: Record<string, unknown> = { ...(fileValue ?? {}) };

	if (flags.count !== undefined) {
		if (!/^\d+$/.test(flags.count.trim())) {
			throw new Error(
				`Invalid --trusted-proxy-count "${flags.count}": must be a non negative integer`,
			);
		}
		merged.trustedProxyCount = Number.parseInt(flags.count.trim(), 10);
	}
	if (flags.header !== undefined) {
		merged.trustedHeader = flags.header;
	}

	if (Object.keys(merged).length === 0) return undefined;

	const result = TrustedProxyConfigSchema.safeParse(merged);
	if (!result.success) {
		const issues = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
		throw new Error(`Invalid trustedProxy settings: ${issues}`);
	}
	return result.data;
}
