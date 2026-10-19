import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { JWK, KeyLike } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

/**
 * Real SVIDs made with the openssl CLI at test time. The commands, for a CA `ca.pem` and a leaf:
 *
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout ca.key -out ca.pem \
 *     -days 3650 -subj "/O=SPIFFE" -addext "basicConstraints=critical,CA:TRUE" \
 *     -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectAltName=URI:spiffe://example.org"
 *   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout leaf.key -out leaf.csr -subj "/"
 *   openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -out leaf.pem -extfile leaf.cnf
 *
 * `leaf.cnf` holds the extensions, see LEAF_OK below. `-noenc` is `-nodes` on OpenSSL 1.1.
 */
export const LEAF_OK = [
	"basicConstraints=critical,CA:FALSE",
	"keyUsage=critical,digitalSignature",
	"extendedKeyUsage=serverAuth,clientAuth",
	"subjectAltName=critical,URI:spiffe://example.org/ns/prod/sa/robot",
];

export function replaceExt(base: string[], prefix: string, line: string | null): string[] {
	const rest = base.filter((l) => !l.startsWith(prefix));
	return line === null ? rest : [...rest, line];
}

export interface Authority {
	dir: string;
	pem: string;
	der: Uint8Array;
	name: string;
}

export interface TestPki {
	dir: string;
	ca: Authority;
	/** Issue a leaf from `signer` (default the root). `ext` is the content of the extension file. */
	leaf(opts?: {
		ext?: string[];
		signer?: Authority;
		key?: "ec" | "rsa";
		days?: number;
		keyName?: string;
	}): { pem: string; der: Uint8Array };
	/** An intermediate CA signed by the root. */
	intermediate(opts?: { ext?: string[]; name?: string; days?: number }): Authority;
	/** A second, unrelated root CA. */
	otherRoot(name: string, uri: string): Authority;
	cleanup(): void;
}

function openssl(dir: string, args: string[]): void {
	execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
}

export function derOf(pem: string): Uint8Array {
	const b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
	return new Uint8Array(Buffer.from(b64, "base64"));
}

export function makePki(): TestPki {
	const dir = mkdtempSync(join(tmpdir(), "spiffe-"));
	let counter = 0;
	const ecKey = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc"];

	function root(name: string, uri: string): Authority {
		openssl(dir, [
			"req",
			"-x509",
			...ecKey,
			"-keyout",
			`${name}.key`,
			"-out",
			`${name}.pem`,
			"-days",
			"3650",
			"-subj",
			`/O=${name}`,
			"-addext",
			"basicConstraints=critical,CA:TRUE",
			"-addext",
			"keyUsage=critical,keyCertSign,cRLSign",
			"-addext",
			`subjectAltName=URI:${uri}`,
		]);
		const pem = readFileSync(join(dir, `${name}.pem`), "utf8");
		return { dir, pem, der: derOf(pem), name };
	}

	const ca = root("ca", "spiffe://example.org");

	return {
		dir,
		ca,
		otherRoot: root,
		intermediate(opts = {}) {
			const name = opts.name ?? `int${++counter}`;
			openssl(dir, [
				"req",
				"-new",
				...ecKey,
				"-keyout",
				`${name}.key`,
				"-out",
				`${name}.csr`,
				"-subj",
				`/O=${name}`,
			]);
			writeFileSync(
				join(dir, `${name}.cnf`),
				`${(opts.ext ?? ["basicConstraints=critical,CA:TRUE", "keyUsage=critical,keyCertSign,cRLSign"]).join("\n")}\n`,
			);
			openssl(dir, [
				"x509",
				"-req",
				"-in",
				`${name}.csr`,
				"-CA",
				"ca.pem",
				"-CAkey",
				"ca.key",
				"-CAcreateserial",
				"-days",
				String(opts.days ?? 3650),
				"-out",
				`${name}.pem`,
				"-extfile",
				`${name}.cnf`,
			]);
			const pem = readFileSync(join(dir, `${name}.pem`), "utf8");
			return { dir, pem, der: derOf(pem), name };
		},
		leaf(opts = {}) {
			const name = opts.keyName ?? `leaf${++counter}`;
			const signer = opts.signer ?? ca;
			const key = opts.key === "rsa" ? ["-newkey", "rsa:2048", "-noenc"] : ecKey;
			openssl(dir, [
				"req",
				"-new",
				...key,
				"-keyout",
				`${name}.key`,
				"-out",
				`${name}.csr`,
				"-subj",
				"/",
			]);
			writeFileSync(join(dir, `${name}.cnf`), `${(opts.ext ?? LEAF_OK).join("\n")}\n`);
			openssl(dir, [
				"x509",
				"-req",
				"-in",
				`${name}.csr`,
				"-CA",
				`${signer.name}.pem`,
				"-CAkey",
				`${signer.name}.key`,
				"-CAcreateserial",
				"-days",
				String(opts.days ?? 1),
				"-out",
				`${name}.pem`,
				"-extfile",
				`${name}.cnf`,
			]);
			const pem = readFileSync(join(dir, `${name}.pem`), "utf8");
			return { pem, der: derOf(pem) };
		},
		cleanup() {
			rmSync(dir, { recursive: true, force: true });
		},
	};
}

export function b64(der: Uint8Array): string {
	return Buffer.from(der).toString("base64");
}

/** A SPIFFE bundle document (SPIFFE Trust Domain and Bundle, section 4). */
export function bundleDoc(opts: {
	cas?: Uint8Array[];
	jwt?: Array<{ kid: string; jwk: JWK }>;
	sequence?: number;
	refreshHint?: number;
	extra?: unknown[];
}): Record<string, unknown> {
	return {
		keys: [
			...(opts.cas ?? []).map((der) => ({ kty: "EC", use: "x509-svid", x5c: [b64(der)] })),
			...(opts.jwt ?? []).map(({ kid, jwk }) => ({ ...jwk, use: "jwt-svid", kid })),
			...(opts.extra ?? []),
		],
		...(opts.sequence !== undefined && { spiffe_sequence: opts.sequence }),
		...(opts.refreshHint !== undefined && { spiffe_refresh_hint: opts.refreshHint }),
	};
}

export interface JwtKey {
	alg: "ES256" | "RS256" | "PS256" | "ES384" | "EdDSA";
	kid: string;
	privateKey: KeyLike;
	publicJwk: JWK;
}

export async function jwtKey(alg: JwtKey["alg"], kid: string): Promise<JwtKey> {
	const pair =
		alg === "EdDSA"
			? await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true })
			: await generateKeyPair(alg, { extractable: true });
	return {
		alg,
		kid,
		privateKey: pair.privateKey,
		publicJwk: (await exportJWK(pair.publicKey)) as JWK,
	};
}

export async function jwtSvid(
	key: JwtKey,
	claims: {
		sub?: string;
		aud?: string | string[];
		exp?: number | null;
		iat?: number | null;
		nbf?: number;
	},
	header: Record<string, unknown> = {},
): Promise<string> {
	const nowSec = Math.floor(Date.now() / 1000);
	const payload: Record<string, unknown> = {};
	if (claims.sub !== undefined) payload.sub = claims.sub;
	if (claims.aud !== undefined) payload.aud = claims.aud;
	if (claims.exp !== null) payload.exp = claims.exp ?? nowSec + 300;
	if (claims.iat !== null && claims.iat !== undefined) payload.iat = claims.iat;
	if (claims.nbf !== undefined) payload.nbf = claims.nbf;
	return new SignJWT(payload)
		.setProtectedHeader({ alg: key.alg, kid: key.kid, typ: "JWT", ...header })
		.sign(key.privateKey);
}
