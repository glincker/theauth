import { MYSQL_TABLE_OPTIONS } from "../ddl/mysql.js";
import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * Quorum (two person) approvals.
 *
 * - `theauth_approval_requests.required_approvals`: how many distinct approvers a request needs. Nullable, and null reads as 1, so every request written before this migration keeps its single approver behavior.
 * - `theauth_approval_votes`: one row per approver who approved. The composite primary key on (approval_id, approver_id) is what stops one approver from being counted twice under concurrent decisions.
 *
 * Additive only. Needs the agent tables (`requires`).
 */
function statements(dialect: Dialect): string[] {
	const t = ddlTypes(dialect);
	const ine = dialect === "postgres" ? "IF NOT EXISTS " : "";
	const opts = t.isMysql ? ` ${MYSQL_TABLE_OPTIONS}` : "";
	return [
		`ALTER TABLE theauth_approval_requests ADD COLUMN ${ine}required_approvals INTEGER`,
		`CREATE TABLE IF NOT EXISTS theauth_approval_votes (
  approval_id  ${t.vc} NOT NULL,
  approver_id  ${t.vc} NOT NULL,
  decided_at   ${t.big} NOT NULL,
  approver_acr TEXT,
  PRIMARY KEY (approval_id, approver_id)
)${opts}`,
	];
}

export const approvalQuorum: Migration = {
	id: "0013",
	name: "approval-quorum",
	requires: ["agent"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
