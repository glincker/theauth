import { and, eq, inArray, or } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { mcpClientBlocks } from "../db/schema.js";
import { toStoreConflict } from "../db/store-conflict.js";
import type { McpClientBlock, McpClientBlockStore } from "./types-cimd.js";

type BlockRow = typeof mcpClientBlocks.$inferSelect;

/** Host rules are case insensitive and ignore a trailing dot. URL rules match the exact client_id. */
export function normalizeBlockValue(kind: "url" | "host", value: string): string {
	const v = value.trim();
	if (kind === "url") return v;
	return v.toLowerCase().replace(/\.$/, "");
}

export function normalizeHosts(hosts: string[]): string[] {
	return hosts.map((h) => normalizeBlockValue("host", h)).filter((h) => h.length > 0);
}

function blockFromRow(row: BlockRow): McpClientBlock {
	return {
		id: row.id,
		kind: row.kind,
		value: row.value,
		reason: row.reason,
		createdBy: row.createdBy,
		createdAt: new Date(row.createdAt * 1000),
	};
}

/** Admin blocks in `theauth_mcp_client_blocks`, shared by every instance on the database. */
export function createDbBlockStore(db: Database): McpClientBlockStore {
	async function findRule(kind: "url" | "host", value: string): Promise<BlockRow | undefined> {
		const rows = await db
			.select()
			.from(mcpClientBlocks)
			.where(and(eq(mcpClientBlocks.kind, kind), eq(mcpClientBlocks.value, value)));
		return rows.find((r) => r.value === value);
	}

	return {
		async findBlock(url, hosts) {
			const hostList = normalizeHosts(hosts);
			const urlRule = and(eq(mcpClientBlocks.kind, "url"), eq(mcpClientBlocks.value, url));
			const hostRule =
				hostList.length > 0
					? and(eq(mcpClientBlocks.kind, "host"), inArray(mcpClientBlocks.value, hostList))
					: undefined;
			const rows = await db
				.select()
				.from(mcpClientBlocks)
				.where(hostRule ? or(urlRule, hostRule) : urlRule);
			// A case insensitive collation can match "/Apps/X" with a rule for "/apps/x": URL rules are exact.
			const hit = rows.find((r) => r.kind === "host" || r.value === url);
			return hit ? blockFromRow(hit) : null;
		},

		/** Idempotent per (kind, value): a repeat or concurrent call returns the existing rule. */
		async addBlock(block) {
			const value = normalizeBlockValue(block.kind, block.value);
			if (!value) throw new Error("A block needs a non empty value");
			const existing = await findRule(block.kind, value);
			if (existing) return blockFromRow(existing);
			try {
				const row = {
					id: generateId(),
					kind: block.kind,
					value,
					reason: block.reason ?? null,
					createdBy: block.createdBy ?? null,
					createdAt: Math.floor(Date.now() / 1000),
				};
				await db.insert(mcpClientBlocks).values(row);
				return blockFromRow(row);
			} catch (error) {
				if (!toStoreConflict(error, "mcp_client_blocks")) throw error;
				const winner = await findRule(block.kind, value);
				if (!winner) throw error;
				return blockFromRow(winner);
			}
		},

		async removeBlock(id) {
			await db.delete(mcpClientBlocks).where(eq(mcpClientBlocks.id, id));
		},

		async listBlocks() {
			const rows = await db.select().from(mcpClientBlocks);
			return rows.map(blockFromRow).sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
		},
	};
}
