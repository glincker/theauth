import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * Per device Apple App Attest assertion counter (`theauth_devices.app_attest_counter`).
 *
 * The counter of an App Attest key only ever grows (Apple's validation guide, assertion step 5). Verifying an assertion advances this column with one conditional UPDATE (`counter < new`), so two requests carrying the same assertion cannot both pass. 0 is the counter right after attestation, so a device that never asserted starts at the right value.
 *
 * Additive only, safe on existing rows (`DEFAULT 0`). Needs the agent tables (`requires`), which hold the device tables.
 */
function statements(dialect: Dialect): string[] {
	const t = ddlTypes(dialect);
	const ine = dialect === "postgres" ? "IF NOT EXISTS " : "";
	return [
		`ALTER TABLE theauth_devices ADD COLUMN ${ine}app_attest_counter ${t.big} NOT NULL DEFAULT 0`,
	];
}

export const deviceAppAttestCounter: Migration = {
	id: "0015",
	name: "device-app-attest-counter",
	requires: ["agent"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
