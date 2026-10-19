import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * Step-up authentication and sender constrained agent tokens.
 *
 * - `theauth_approval_requests.required_acr` and `max_auth_age`: what the approver must prove before
 *   the request can be approved (RFC 9470). Both nullable: a null row keeps the old behavior.
 * - `theauth_agents.cnf`: the confirmation claim (RFC 7800) the agent token is bound to, for example
 *   `{"jkt":"..."}` for DPoP (RFC 9449) or `{"x5t#S256":"..."}` for mutual TLS (RFC 8705). Null means
 *   a plain bearer token.
 *
 * Additive and nullable, so rows written before this migration stay valid.
 */
function statements(dialect: Dialect): string[] {
	const t = ddlTypes(dialect);
	const ine = dialect === "postgres" ? "IF NOT EXISTS " : "";
	return [
		`ALTER TABLE theauth_approval_requests ADD COLUMN ${ine}required_acr TEXT`,
		`ALTER TABLE theauth_approval_requests ADD COLUMN ${ine}max_auth_age INTEGER`,
		`ALTER TABLE theauth_agents ADD COLUMN ${ine}cnf ${t.json}`,
	];
}

export const stepUpAndConfirmation: Migration = {
	id: "0009",
	name: "step-up-and-confirmation",
	requires: ["agent"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
