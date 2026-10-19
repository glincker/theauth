import { calculateJwkThumbprint } from "jose";
import { spkiInfo } from "./x509.js";

/** RFC 7638 SHA-256 thumbprint of an EC P-256 or P-384 SubjectPublicKeyInfo, or undefined for anything else. */
export async function keyThumbprint(spki: Uint8Array): Promise<string | undefined> {
	try {
		const info = spkiInfo(spki);
		if (info.alg !== "1.2.840.10045.2.1") return undefined;
		const namedCurve =
			info.curve === "1.3.132.0.34"
				? "P-384"
				: info.curve === "1.2.840.10045.3.1.7"
					? "P-256"
					: undefined;
		if (!namedCurve) return undefined;
		const copy = new Uint8Array(new ArrayBuffer(spki.length));
		copy.set(spki);
		const key = await globalThis.crypto.subtle.importKey(
			"spki",
			copy,
			{ name: "ECDSA", namedCurve },
			true,
			["verify"],
		);
		const jwk = await globalThis.crypto.subtle.exportKey("jwk", key);
		return await calculateJwkThumbprint(jwk, "sha256");
	} catch {
		return undefined;
	}
}
