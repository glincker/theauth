import { primaryKey, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { bigintNumber } from "./columns.js";

/**
 * Shared MCP revocation list (migration 0007). `jti`, `dlg` and `agent` rows deny outright;
 * `sub` and `client` rows are `iat` watermarks. Only ids are stored, never token values.
 */
export const mcpRevocations = sqliteTable(
	"theauth_mcp_revocations",
	{
		kind: text("kind", { enum: ["jti", "dlg", "agent", "sub", "client"] }).notNull(),
		id: text("id").notNull(),
		/** Epoch milliseconds of the (latest) revocation. */
		revokedAtMs: bigintNumber("revoked_at_ms").notNull(),
		/** Epoch seconds after which the row can be pruned. Plain number: TIMESTAMP_COLUMNS is frozen with the baseline. */
		expiresAt: bigintNumber("expires_at").notNull(),
		reason: text("reason").notNull(),
		/** Root delegation id of a cascade, or the revoking actor. Never a token value. */
		sourceId: text("source_id"),
	},
	(t) => [primaryKey({ columns: [t.kind, t.id] })],
);
