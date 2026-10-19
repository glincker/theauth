import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * How the user authenticated, kept with the grant so tokens carry `acr`, `amr` and `auth_time` (RFC 9470, RFC 9068).
 *
 * `theauth_oauth_authorization_codes` and `theauth_oauth_access_tokens` get `auth_acr`, `auth_amr` (space separated RFC 8176 values) and `auth_time` (epoch seconds). The token row matters for refresh: a refreshed access token keeps the `auth_time` of the original login.
 *
 * Additive and nullable, so rows written before this migration stay valid and simply carry no evidence.
 */
function statements(dialect: Dialect): string[] {
	const t = ddlTypes(dialect);
	const ine = dialect === "postgres" ? "IF NOT EXISTS " : "";
	const out: string[] = [];
	for (const table of ["theauth_oauth_authorization_codes", "theauth_oauth_access_tokens"]) {
		out.push(
			`ALTER TABLE ${table} ADD COLUMN ${ine}auth_acr TEXT`,
			`ALTER TABLE ${table} ADD COLUMN ${ine}auth_amr TEXT`,
			`ALTER TABLE ${table} ADD COLUMN ${ine}auth_time ${t.big}`,
		);
	}
	return out;
}

export const oauthAuthEvidence: Migration = {
	id: "0011",
	name: "oauth-auth-evidence",
	requires: ["oauth"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
