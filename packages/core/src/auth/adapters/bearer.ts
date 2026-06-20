/**
 * JWT bearer-token auth adapter.
 *
 * Verifies a JWT from the `Authorization: Bearer <token>` header using a
 * symmetric secret (HS256/HS384/HS512).  Extracts `sub`, `email`, `name`, and
 * `picture` from the payload and returns them as a `ResolvedUser`.
 *
 * @example
 * ```typescript
 * import { bearerAuth } from 'theauth/auth';
 *
 * const adapter = bearerAuth({
 *   secret: process.env.JWT_SECRET,
 *   issuer: 'https://my-app.example.com',
 *   audience: 'theauth',
 * });
 * ```
 */

import { jwtVerify } from "jose";
import { z } from "zod";
import type { AuthAdapter, ResolvedUser } from "../types.js";

// ---------------------------------------------------------------------------
// Options schema
// ---------------------------------------------------------------------------

const BearerAuthOptionsSchema = z.object({
	/**
	 * Secret used to verify HS256/HS384/HS512 tokens.
	 * Must be at least 32 characters.
	 */
	secret: z.string().min(1, "secret is required"),
	/** Expected `iss` claim.  Omit to skip issuer validation. */
	issuer: z.string().optional(),
	/** Expected `aud` claim.  Omit to skip audience validation. */
	audience: z.string().optional(),
});

export type BearerAuthOptions = z.infer<typeof BearerAuthOptionsSchema>;

// ---------------------------------------------------------------------------
// Payload schema – only the fields TheAuth cares about
// ---------------------------------------------------------------------------

const JwtPayloadSchema = z.object({
	sub: z.string(),
	email: z.string().optional(),
	name: z.string().optional(),
	// Both `picture` (OIDC) and `image` (custom) are accepted.
	picture: z.string().optional(),
	image: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an `AuthAdapter` that validates a JWT from the `Authorization: Bearer`
 * header and maps its claims to a `ResolvedUser`.
 *
 * Returns `null` when:
 * - No `Authorization` header is present
 * - The header does not use the `Bearer` scheme
 * - The JWT signature is invalid, the token is expired, or claims do not match
 *   the configured `issuer` / `audience`
 */
export function bearerAuth(options: BearerAuthOptions): AuthAdapter {
	const parsed = BearerAuthOptionsSchema.parse(options);

	// Pre-compute the key bytes once so we don't recreate them per request.
	const keyObject = new TextEncoder().encode(parsed.secret);

	return {
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			const authHeader = request.headers.get("authorization");
			if (!authHeader) return null;

			const [scheme, token] = authHeader.split(" ");
			if (scheme?.toLowerCase() !== "bearer" || !token) return null;

			try {
				const { payload } = await jwtVerify(token, keyObject, {
					issuer: parsed.issuer,
					audience: parsed.audience,
				});

				const claims = JwtPayloadSchema.safeParse(payload);
				if (!claims.success) return null;

				const { sub, email, name, picture, image } = claims.data;

				// Strip undefined fields from metadata so callers get a clean object.
				const metadata: Record<string, unknown> = {};
				for (const [k, v] of Object.entries(payload)) {
					if (
						![
							"sub",
							"email",
							"name",
							"picture",
							"image",
							"iat",
							"exp",
							"iss",
							"aud",
							"nbf",
							"jti",
						].includes(k)
					) {
						metadata[k] = v;
					}
				}

				return {
					id: sub,
					...(email !== undefined && { email }),
					...(name !== undefined && { name }),
					...(picture !== undefined || image !== undefined ? { image: picture ?? image } : {}),
					...(Object.keys(metadata).length > 0 && { metadata }),
				};
			} catch {
				// Token verification failed (expired, bad signature, wrong issuer, etc.)
				return null;
			}
		},
	};
}
