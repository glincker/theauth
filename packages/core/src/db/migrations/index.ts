import type { Migration } from "../migrate/types.js";
import { baseline } from "./0000-baseline.js";
import { relationAndCacheHit } from "./0001-relation-and-cache-hit.js";
import { auditDecisionCode } from "./0002-audit-decision-code.js";
import { epochTimestamps } from "./0003-epoch-timestamps.js";
import { auditRecordedAtMs } from "./0004-audit-recorded-at-ms.js";
import { auditEvent } from "./0005-audit-event.js";
import { mcpStores } from "./0006-mcp-stores.js";
import { mcpRevocation } from "./0007-mcp-revocation.js";
import { cimd } from "./0008-cimd.js";

/**
 * Every migration, in order. Ids are append only and never reused.
 * Reserved for upcoming work: none.
 */
export const MIGRATIONS: readonly Migration[] = [
	baseline,
	relationAndCacheHit,
	auditDecisionCode,
	epochTimestamps,
	auditRecordedAtMs,
	auditEvent,
	mcpStores,
	mcpRevocation,
	cimd,
];

export const BASELINE_ID = baseline.id;
