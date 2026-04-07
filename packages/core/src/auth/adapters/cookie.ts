/**
 * JWT cookie auth adapter.
 *
 * Verifies a JWT from an httpOnly cookie using a symmetric secret
 * (HS256/HS384/HS512). Extracts standard claims and returns them as a
 * `ResolvedUser`. Designed for backends that set JWT tokens in cookies
 * (e.g. a Go API with GitHub OAuth).
 *
 * @example
 * ```typescript
 * import { cookieAuth } from 'kavachos/auth';
 *
 * const adapter = cookieAuth({
 *   secret: process.env.JWT_SECRET,
 *   cookieName: 'glinr_token',
 * });
 * ```
 */

import { jwtVerify } from "jose";
import { z } from "zod";
import type { AuthAdapter, ResolvedUser } from "../types.js";

// ---------------------------------------------------------------------------
// Options schema
// ---------------------------------------------------------------------------

const CookieAuthOptionsSchema = z.object({
	/** Secret used to verify HS256/HS384/HS512 tokens. */
	secret: z.string().min(1, "secret is required"),
	/** Name of the cookie containing the JWT. Defaults to "token". */
	cookieName: z.string().default("token"),
	/** Expected `iss` claim. Omit to skip issuer validation. */
	issuer: z.string().optional(),
	/** Expected `aud` claim. Omit to skip audience validation. */
	audience: z.string().optional(),
	/**
	 * Map JWT claim names to ResolvedUser fields.
	 * Defaults: { id: "user_id", email: "email", name: "name", image: "avatar" }
	 */
	claimMapping: z
		.object({
			id: z.string().default("user_id"),
			email: z.string().default("email"),
			name: z.string().default("name"),
			image: z.string().default("avatar"),
		})
		.default({}),
});

export type CookieAuthOptions = z.input<typeof CookieAuthOptionsSchema>;

// ---------------------------------------------------------------------------
// Cookie parser
// ---------------------------------------------------------------------------

function parseCookies(cookieHeader: string): Map<string, string> {
	const cookies = new Map<string, string>();
	for (const pair of cookieHeader.split(";")) {
		const eqIndex = pair.indexOf("=");
		if (eqIndex === -1) continue;
		const key = pair.slice(0, eqIndex).trim();
		const value = pair.slice(eqIndex + 1).trim();
		if (key) cookies.set(key, value);
	}
	return cookies;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an `AuthAdapter` that validates a JWT from an httpOnly cookie
 * and maps its claims to a `ResolvedUser`.
 *
 * Returns `null` when:
 * - No cookie header is present
 * - The named cookie is missing
 * - The JWT signature is invalid, the token is expired, or claims do not
 *   match the configured `issuer` / `audience`
 * - The JWT has no `sub` or mapped ID claim
 */
export function cookieAuth(options: CookieAuthOptions): AuthAdapter {
	const parsed = CookieAuthOptionsSchema.parse(options);
	const keyObject = new TextEncoder().encode(parsed.secret);

	return {
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			const cookieHeader = request.headers.get("cookie");
			if (!cookieHeader) return null;

			const cookies = parseCookies(cookieHeader);
			const token = cookies.get(parsed.cookieName);
			if (!token) return null;

			try {
				const { payload } = await jwtVerify(token, keyObject, {
					issuer: parsed.issuer,
					audience: parsed.audience,
				});

				// Extract user ID — try mapped claim first, fall back to `sub`
				const id =
					(payload[parsed.claimMapping.id] as string | undefined) ??
					(payload.sub as string | undefined);
				if (!id) return null;

				const email = payload[parsed.claimMapping.email] as string | undefined;
				const name = payload[parsed.claimMapping.name] as string | undefined;
				const image = payload[parsed.claimMapping.image] as string | undefined;

				// Collect extra claims as metadata
				const reserved = new Set([
					"sub",
					"iat",
					"exp",
					"iss",
					"aud",
					"nbf",
					"jti",
					parsed.claimMapping.id,
					parsed.claimMapping.email,
					parsed.claimMapping.name,
					parsed.claimMapping.image,
				]);
				const metadata: Record<string, unknown> = {};
				for (const [k, v] of Object.entries(payload)) {
					if (!reserved.has(k)) {
						metadata[k] = v;
					}
				}

				return {
					id,
					...(email !== undefined && { email }),
					...(name !== undefined && { name }),
					...(image !== undefined && { image }),
					...(Object.keys(metadata).length > 0 && { metadata }),
				};
			} catch {
				return null;
			}
		},
	};
}
