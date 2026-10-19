import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * Refresh token families for the OIDC provider (RFC 9700 section 4.14.2).
 *
 * `theauth_oidc_refresh_tokens.family_id` ties every rotated refresh token to the first one issued from an authorization code. Presenting a token that was already rotated revokes the whole family.
 *
 * Additive and nullable, so tokens issued before this migration stay valid. They have no family, and a reuse of one of them revokes every refresh token of the same user and client instead.
 */
function statements(dialect: Dialect): string[] {
	const t = ddlTypes(dialect);
	const ine = dialect === "postgres" ? "IF NOT EXISTS " : "";
	const idx =
		dialect === "mysql"
			? "CREATE INDEX theauth_oidc_refresh_family ON theauth_oidc_refresh_tokens (family_id)"
			: "CREATE INDEX IF NOT EXISTS theauth_oidc_refresh_family ON theauth_oidc_refresh_tokens (family_id)";
	return [`ALTER TABLE theauth_oidc_refresh_tokens ADD COLUMN ${ine}family_id ${t.vc}`, idx];
}

export const oidcRefreshFamily: Migration = {
	id: "0012",
	name: "oidc-refresh-family",
	requires: ["oidcProvider"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
