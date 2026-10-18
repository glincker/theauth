import type { Migration } from "../migrate/types.js";
import { baseline } from "./0000-baseline.js";
import { relationAndCacheHit } from "./0001-relation-and-cache-hit.js";
import { auditDecisionCode } from "./0002-audit-decision-code.js";
import { auditRecordedAtMs } from "./0003-audit-recorded-at-ms.js";

/**
 * Every migration, in order. Ids are append only and never reused.
 * Reserved for upcoming work: 0004 audit event, 0005 oauth stores, 0006 MCP revocation.
 */
export const MIGRATIONS: readonly Migration[] = [
	baseline,
	relationAndCacheHit,
	auditDecisionCode,
	auditRecordedAtMs,
];

export const BASELINE_ID = baseline.id;
