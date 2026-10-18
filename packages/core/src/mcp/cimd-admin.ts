import { emitCimdHook } from "./cimd-events.js";
import { canonicalizeClientIdUrl, checkClientIdUrl } from "./cimd-url.js";
import { invalidateFreshnessCache } from "./freshness.js";
import { revocationRowExpiry } from "./revocation-bus.js";
import type { McpRevocationStore } from "./revocation-types.js";
import type { McpAuthContext } from "./types.js";
import type { McpCimdAdmin, McpCimdEvent } from "./types-cimd.js";
import { CIMD_DISABLED_REASON_BLOCKED } from "./types-cimd.js";

const NO_BLOCK_STORE =
	"This MCP module has no block store. Pass `auth` to createMcpModule, or a `blocks` store, and turn on clientIdMetadataDocuments.";

/** Fire and forget: an event hook must never slow or break the request path. */
export function emitCimdEvent(ctx: McpAuthContext, event: McpCimdEvent): void {
	emitCimdHook(ctx.config.clientIdMetadataDocuments, event);
}

function isRevocationStore(value: unknown): value is McpRevocationStore {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof (value as Record<string, unknown>).revokeMany === "function"
	);
}

/** A host rule is a bare hostname: "evil.example". A leading "*." is accepted and means the same (subdomains are always covered). */
function cleanHostRule(value: string): string {
	const host = value.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
	if (host.length === 0 || /[/:@?#\s*]/.test(host)) {
		throw new Error("A host block must be a bare hostname such as evil.example");
	}
	return host;
}

/** A URL rule matches the exact client_id, so it must be in canonical form. */
function cleanUrlRule(value: string): string {
	const canonical = canonicalizeClientIdUrl(value.trim());
	if (!canonical) throw new Error("A URL block must be a valid https client_id URL");
	return canonical;
}

/**
 * The admin API behind `mcp.cimd`. It trusts its caller: expose it only to operators, never to OAuth clients.
 * `refresh` is supplied by the caller because forcing a fetch lives with the resolver.
 */
export function createCimdAdmin(
	ctx: McpAuthContext,
	refresh: McpCimdAdmin["refresh"],
): McpCimdAdmin {
	const requireBlocks = () => {
		if (!ctx.clientBlocks) throw new Error(NO_BLOCK_STORE);
		return ctx.clientBlocks;
	};

	/** `disable: false` (host rules) only deletes the token rows, so unblocking the host later does not bring old refresh tokens back and the client can consent again from scratch. */
	async function killClient(clientId: string, disable = true): Promise<void> {
		const stored = disable ? await ctx.findClient(clientId) : null;
		if (stored && stored.clientId === clientId) {
			if (ctx.setClientDisabled) {
				await ctx.setClientDisabled(clientId, true, CIMD_DISABLED_REASON_BLOCKED);
			} else {
				await ctx.storeClient({
					...stored,
					disabled: true,
					disabledReason: CIMD_DISABLED_REASON_BLOCKED,
				});
			}
		}
		const revoked = await ctx.revokeClientTokens?.(clientId);
		const denylist = ctx.config.jtiDenylist;
		if (revoked && denylist) {
			for (const { jti, expiresAt } of revoked.jtis) await denylist.revoke(jti, expiresAt);
		}
		// A shared revocation store also gets a `client` watermark row: every token this client holds is
		// refused at once in live mode, on every instance, including tokens a token store forgot about.
		if (isRevocationStore(denylist)) {
			const now = new Date();
			const ttlMs = (ctx.config.accessTokenTtl ?? 3600) * 1000 + 60_000;
			await denylist.revokeMany([
				{
					kind: "client",
					id: clientId,
					expiresAt: revocationRowExpiry(new Date(now.getTime() + ttlMs), now),
					reason: "cimd.block",
				},
			]);
			invalidateFreshnessCache(ctx);
		}
	}

	return {
		async block(input) {
			const blocks = requireBlocks();
			const value = input.kind === "host" ? cleanHostRule(input.value) : cleanUrlRule(input.value);
			if (value.length === 0) throw new Error("A block needs a value");
			// The rule goes in first so no new fetch or grant can slip in while the client is torn down.
			const created = await blocks.addBlock({
				kind: input.kind,
				value,
				reason: input.reason ?? null,
				createdBy: input.createdBy ?? null,
			});
			emitCimdEvent(ctx, { type: "cimd.blocked", clientId: value, rule: `${input.kind}:${value}` });
			// A URL rule names the stored client. A host rule is enforced by the resolver on every call and, when the store can list CIMD clients, also revokes their tokens.
			if (input.kind === "url") {
				await killClient(value);
			} else if (ctx.listCimdClientIds) {
				// The resolver already refuses the host; this also deletes the tokens so they stay dead after an unblock.
				for (const id of await ctx.listCimdClientIds()) {
					const parsed = checkClientIdUrl(id);
					if (parsed.ok && (parsed.host === value || parsed.host.endsWith(`.${value}`))) {
						await killClient(id, false);
					}
				}
			}
			return created;
		},

		unblock: (id) => requireBlocks().removeBlock(id),

		listBlocks: () => requireBlocks().listBlocks(),

		refresh,

		async enable(clientId) {
			if (ctx.setClientDisabled) {
				await ctx.setClientDisabled(clientId, false, null);
				return;
			}
			const stored = await ctx.findClient(clientId);
			if (!stored) throw new Error(`Unknown client: ${clientId}`);
			await ctx.storeClient({ ...stored, disabled: false, disabledReason: null });
		},

		inspect: (clientId) => ctx.findClient(clientId),
	};
}
