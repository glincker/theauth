import type { Dialect } from "../migrate/types.js";
import { agentsExtraDdl } from "./agents-extra.js";
import { auditDdl } from "./audit.js";
import { coreDdl } from "./core.js";
import { enterpriseDdl } from "./enterprise.js";
import { humanDdl } from "./human.js";
import { oauthDdl } from "./oauth.js";
import { orgDdl } from "./org.js";
import type { TaggedStatement } from "./types.js";
import { ddlTypes } from "./types.js";

export type { TimestampColumn, TimestampUnit } from "./timestamp-columns.js";
export { TIMESTAMP_COLUMNS } from "./timestamp-columns.js";
export type { DdlTypes, TaggedStatement } from "./types.js";
export { ddlTypes } from "./types.js";

/**
 * Baseline DDL for every TheAuth table, in dependency order (a table always follows the tables its foreign keys point at), each statement tagged with its feature.
 */
export function baselineStatements(dialect: Dialect): TaggedStatement[] {
	const t = ddlTypes(dialect);
	return [
		...coreDdl(t),
		...auditDdl(t),
		...agentsExtraDdl(t),
		...oauthDdl(t),
		...humanDdl(t),
		...orgDdl(t),
		...enterpriseDdl(t),
	];
}
