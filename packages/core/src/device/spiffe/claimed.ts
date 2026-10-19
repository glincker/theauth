import { parseCertificate } from "../attestation/x509.js";
import { parseSpiffeId } from "./spiffe-id.js";
import { sanUris } from "./x509-info.js";
import { certThumbprint } from "./x509-svid.js";

/**
 * Read the SPIFFE ID an SVID names without checking any signature, for audit rows of failed attempts.
 * The value is a claim: never use it to authenticate. Returns null when no valid id can be read.
 */
export async function claimedSpiffeId(
	presentation: { kind: "x509"; chain: Uint8Array[] | string } | { kind: "jwt"; token: string },
	chainOf: (input: Uint8Array[] | string) => Uint8Array[] | null,
): Promise<{ spiffeId: string; thumbprint?: string } | null> {
	try {
		if (presentation.kind === "jwt") {
			const part = presentation.token.split(".")[1];
			if (!part || presentation.token.length > 16_384) return null;
			const padded = part.replace(/-/g, "+").replace(/_/g, "/");
			const json = new TextDecoder().decode(
				Uint8Array.from(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4)), (c) =>
					c.charCodeAt(0),
				),
			);
			const sub = (JSON.parse(json) as { sub?: unknown }).sub;
			if (typeof sub !== "string") return null;
			const id = parseSpiffeId(sub);
			return id.ok ? { spiffeId: id.id } : null;
		}
		const chain = chainOf(presentation.chain);
		const leaf = chain?.[0];
		if (!leaf) return null;
		const cert = parseCertificate(leaf);
		const uris = sanUris(cert).uris;
		const id = uris.length === 1 ? parseSpiffeId(uris[0] as string) : null;
		if (!id?.ok) return null;
		return { spiffeId: id.id, thumbprint: await certThumbprint(leaf) };
	} catch {
		return null;
	}
}
