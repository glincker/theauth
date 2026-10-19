import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const ATTEST_HELP = `
theauth device attest android --evidence <file> --nonce <nonce> --revocation google|off [options]
theauth device attest apple   --evidence <file> --nonce <nonce> --app-id <TeamID.BundleID> [options]
theauth device attest tpm     --evidence <file> --nonce <nonce> --root <file> | --allow-unverified-ak [options]
theauth device attest apple-assertion --assertion <file> --client-data <file> --app-id <id> --public-key <base64> --previous-counter <n>
theauth device attest apple-receipt   --receipt <file> [--app-id <id>] [--public-key <base64>] [--root <file>]

Checks evidence offline with the same verifier the enrollment hook uses. No config file is needed.
Exit code 0 when the evidence is accepted, 1 when it is refused.

android: the evidence file is a JSON array of base64 DER certificates, leaf first (KeyStore.getCertificateChain).
apple:   the evidence file is JSON { "attestation": "<base64>", "keyId": "<base64>" } (App Attest attestKey output).
tpm:     the evidence file is JSON { "akPublic", "quote", "signature", "pcrs", "akCertificates" }, see the IoT docs.
apple-assertion: --assertion is the base64 assertion object, --client-data the exact bytes the app hashed, --public-key the
         attestedPublicKey claim stored at enrollment, --previous-counter the highest counter accepted so far (0 after attestation).
apple-receipt:   --receipt is the base64 receipt (CMS) Apple returned with an attestation or assertion.
The TPM certify verifier needs the server side activation store, so it has no offline command here (the Go CLI has one).

Common options:
  --evidence <file>         Evidence file
  --nonce <nonce>           The nonce the device bound into its evidence
  --root <file>             Trust anchor, PEM or base64 DER (repeatable). With --root only these are trusted
  --challenge utf8|base64url|hex   Encoding of the nonce (default utf8, tpm quotes often use hex)
  --key-thumbprint <t>      RFC 7638 thumbprint the attested key must have (android and apple, jwk credential binding)
  --now <iso time>          Verify as of this time
  --json                    Machine readable output

android options:
  --revocation google|off   Check serials against Google's status list, or skip (required, on purpose)
  --min-level tee|strongbox Lowest accepted security level (default tee)
  --boot verified|verified_or_self_signed|any   Boot policy (default verified)

apple options:
  --app-id <id>             Accepted App ID, TeamID.BundleID (required, repeatable)
  --environment production|development|any   AAGUID to accept (default production)
  --client-data-hash sha256|raw   How the app derived clientDataHash from its client data (default sha256)
  --bind client-data|attested-key|none   How the enrolled key is tied in (default: client-data when --key-thumbprint is given, else none)

tpm options:
  --allow-unverified-ak     Accept an attestation key without a certificate chain (development only)
  --pcr <bank>:<index>=<hex>   Expected PCR value, for example sha256:7=ab12... (repeatable)

Accepted evidence also prints the policy facts (securityLevel, bootState, appIds) that an attestation constraint reads.
`;

export interface AttestArgs {
	format: "android" | "apple" | "tpm" | "apple-assertion" | "apple-receipt";
	evidence?: string;
	assertion?: string;
	clientData?: string;
	publicKey?: string;
	previousCounter: number;
	receipt?: string;
	nonce?: string;
	revocation?: "google" | "off";
	roots: string[];
	minLevel: "trusted_environment" | "strongbox";
	boot: "verified" | "verified_or_self_signed" | "any";
	keyThumbprint?: string;
	challenge: "utf8" | "base64url" | "hex";
	appIds: string[];
	environment: "production" | "development" | "any";
	clientDataHash: "sha256" | "raw";
	bind?: "client-data" | "attested-key" | "none";
	allowUnverifiedAk: boolean;
	pcrs: Record<string, Record<number, string>>;
	now?: Date;
	json: boolean;
	error: string | null;
}

const FORMATS = ["android", "apple", "tpm", "apple-assertion", "apple-receipt"] as const;

/** Parse the arguments after `device attest`. */
export function parseAttestArgs(args: string[]): AttestArgs {
	const [format, ...rest] = args;
	const out: AttestArgs = {
		format: FORMATS.find((f) => f === format) ?? "android",
		roots: [],
		minLevel: "trusted_environment",
		boot: "verified",
		challenge: "utf8",
		appIds: [],
		environment: "production",
		clientDataHash: "sha256",
		allowUnverifiedAk: false,
		previousCounter: 0,
		pcrs: {},
		json: false,
		error: null,
	};
	if (!FORMATS.some((f) => f === format)) {
		out.error =
			"Supported attestation formats: android, apple, tpm, apple-assertion, apple-receipt";
		return out;
	}
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] ?? "";
		const v = rest[i + 1];
		switch (a) {
			case "--json":
				out.json = true;
				break;
			case "--allow-unverified-ak":
				out.allowUnverifiedAk = true;
				break;
			case "--evidence":
				out.evidence = v;
				i++;
				break;
			case "--assertion":
				out.assertion = v;
				i++;
				break;
			case "--client-data":
				out.clientData = v;
				i++;
				break;
			case "--public-key":
				out.publicKey = v;
				i++;
				break;
			case "--receipt":
				out.receipt = v;
				i++;
				break;
			case "--previous-counter": {
				const n = Number(v);
				if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
					out.error ??= "--previous-counter must be an integer from 0 to 4294967295";
				} else out.previousCounter = n;
				i++;
				break;
			}
			case "--nonce":
				out.nonce = v;
				i++;
				break;
			case "--root":
				if (v) out.roots.push(v);
				i++;
				break;
			case "--app-id":
				if (v) out.appIds.push(v);
				i++;
				break;
			case "--key-thumbprint":
				out.keyThumbprint = v;
				i++;
				break;
			case "--revocation":
				if (v === "google" || v === "off") out.revocation = v;
				else out.error ??= "--revocation must be google or off";
				i++;
				break;
			case "--min-level":
				if (v === "tee") out.minLevel = "trusted_environment";
				else if (v === "strongbox") out.minLevel = "strongbox";
				else out.error ??= "--min-level must be tee or strongbox";
				i++;
				break;
			case "--boot":
				if (v === "verified" || v === "verified_or_self_signed" || v === "any") out.boot = v;
				else out.error ??= "--boot must be verified, verified_or_self_signed or any";
				i++;
				break;
			case "--challenge":
				if (v === "utf8" || v === "base64url" || v === "hex") out.challenge = v;
				else out.error ??= "--challenge must be utf8, base64url or hex";
				i++;
				break;
			case "--environment":
				if (v === "production" || v === "development" || v === "any") out.environment = v;
				else out.error ??= "--environment must be production, development or any";
				i++;
				break;
			case "--bind":
				if (v === "client-data" || v === "attested-key" || v === "none") out.bind = v;
				else out.error ??= "--bind must be client-data, attested-key or none";
				i++;
				break;
			case "--client-data-hash":
				if (v === "sha256" || v === "raw") out.clientDataHash = v;
				else out.error ??= "--client-data-hash must be sha256 or raw";
				i++;
				break;
			case "--pcr": {
				const m = /^(sha1|sha256|sha384|sha512):(\d{1,2})=([0-9a-fA-F]+)$/.exec(v ?? "");
				if (!m) out.error ??= "--pcr must look like sha256:7=<hex>";
				else {
					const bank = m[1] as string;
					out.pcrs[bank] = { ...out.pcrs[bank], [Number(m[2])]: m[3] as string };
				}
				i++;
				break;
			}
			case "--now": {
				const d = new Date(v ?? "");
				if (Number.isNaN(d.getTime())) out.error ??= "--now needs an ISO time";
				else out.now = d;
				i++;
				break;
			}
			default:
				out.error ??= `Unknown argument: ${a}`;
		}
	}
	if (!out.error && out.format === "apple-assertion") {
		if (!out.assertion) out.error = "Missing --assertion <file>";
		else if (!out.clientData) out.error = "Missing --client-data <file>";
		else if (!out.publicKey) out.error = "Missing --public-key <base64>";
		else if (out.appIds.length !== 1) out.error = "Pass exactly one --app-id <TeamID.BundleID>";
	} else if (!out.error && out.format === "apple-receipt") {
		if (!out.receipt) out.error = "Missing --receipt <file>";
	} else if (!out.error) {
		if (!out.evidence) out.error = "Missing --evidence <file>";
		else if (!out.nonce) out.error = "Missing --nonce";
		else if (out.format === "android" && !out.revocation) {
			out.error = "Missing --revocation google|off";
		} else if (out.format === "apple" && out.appIds.length === 0) {
			out.error = "Missing --app-id <TeamID.BundleID>";
		} else if (out.format === "tpm" && out.roots.length === 0 && !out.allowUnverifiedAk) {
			out.error = "Pass --root <file> or --allow-unverified-ak";
		}
	}
	return out;
}

async function buildVerifier(args: AttestArgs, roots: string[]) {
	const core = await import("@glinr/theauth");
	const now = args.now ? { now: () => args.now as Date } : {};
	if (args.format === "apple") {
		return core.createAppleAppAttestVerifier({
			appIds: args.appIds,
			...(roots.length > 0 && { roots }),
			environment: args.environment,
			bind: args.bind ?? (args.keyThumbprint !== undefined ? "client-data" : "none"),
			clientDataHash: args.clientDataHash,
			challengeEncoding: args.challenge,
			...now,
		});
	}
	if (args.format === "tpm") {
		return core.createTpm2QuoteVerifier({
			...(roots.length > 0 && { roots }),
			allowUnverifiedAk: args.allowUnverifiedAk,
			challengeEncoding: args.challenge,
			expectedPcrs: args.pcrs,
			...now,
		});
	}
	return core.createAndroidKeyAttestationVerifier({
		revocation: args.revocation === "google" ? core.googleRevocationList() : "disabled",
		...(roots.length > 0 && { roots }),
		minSecurityLevel: args.minLevel === "strongbox" ? "strongbox" : "trusted_environment",
		bootPolicy: args.boot,
		bindKey: args.keyThumbprint !== undefined,
		challengeEncoding: args.challenge,
		...now,
	});
}

async function runAssertionOrReceipt(
	args: AttestArgs,
	roots: string[],
): Promise<{ ok: true; claims: Record<string, unknown> } | { ok: false; reason: string }> {
	const core = await import("@glinr/theauth");
	if (args.format === "apple-assertion") {
		const assertion = (await readFile(resolve(args.assertion ?? ""), "utf8")).trim();
		const clientData = await readFile(resolve(args.clientData ?? ""));
		const r = await core.verifyAppleAssertion({
			assertion,
			clientData: new Uint8Array(clientData),
			appId: args.appIds[0] ?? "",
			publicKey: args.publicKey ?? "",
			previousCounter: args.previousCounter,
		});
		return r.ok ? { ok: true, claims: { counter: r.counter, flags: r.flags } } : r;
	}
	const receipt = (await readFile(resolve(args.receipt ?? ""), "utf8")).trim();
	const r = await core.verifyAppleReceipt(receipt, {
		...(args.appIds[0] !== undefined && { appId: args.appIds[0] }),
		...(args.publicKey !== undefined && { publicKey: args.publicKey }),
		...(roots.length > 0 && { roots }),
		...(args.now && { now: () => args.now as Date }),
	});
	if (!r.ok) return r;
	const x = r.receipt;
	return {
		ok: true,
		claims: {
			appId: x.appId,
			type: x.type,
			...(x.environment !== undefined && { environment: x.environment }),
			creationTime: x.creationTime.toISOString(),
			...(x.notBefore && { notBefore: x.notBefore.toISOString() }),
			...(x.expirationTime && { expirationTime: x.expirationTime.toISOString() }),
			...(x.riskMetric !== undefined && { riskMetric: x.riskMetric }),
			token: x.token,
			...(x.attestedKeyThumbprint !== undefined && {
				attestedKeyThumbprint: x.attestedKeyThumbprint,
			}),
		},
	};
}

/** Run the check and return the text to print plus whether the evidence was accepted. */
export async function runAttest(args: AttestArgs): Promise<{ text: string; ok: boolean }> {
	const roots = await Promise.all(args.roots.map((f) => readFile(resolve(f), "utf8")));
	if (args.format === "apple-assertion" || args.format === "apple-receipt") {
		return render(await runAssertionOrReceipt(args, roots), args.json);
	}
	const evidence = await readFile(resolve(args.evidence ?? ""), "utf8");
	const verify = await buildVerifier(args, roots);
	const result = await verify({
		evidence,
		nonce: args.nonce ?? "",
		enrollmentId: "cli",
		...(args.keyThumbprint !== undefined && {
			credentialKind: "jwk" as const,
			credentialKeyThumbprint: args.keyThumbprint,
		}),
	});
	return render(result.ok ? { ok: true, claims: result.claims ?? {} } : result, args.json);
}

async function render(
	result: { ok: true; claims: Record<string, unknown> } | { ok: false; reason: string },
	json: boolean,
): Promise<{ text: string; ok: boolean }> {
	const core = await import("@glinr/theauth");
	const facts = result.ok ? core.attestationFacts(result.claims) : undefined;
	if (json) {
		return {
			text: JSON.stringify(result.ok ? { ...result, ...(facts && { facts }) } : result, null, 2),
			ok: result.ok,
		};
	}
	if (!result.ok) return { text: `Refused: ${result.reason}`, ok: false };
	const lines = Object.entries(result.claims).map(([k, val]) => `  ${k}: ${JSON.stringify(val)}`);
	const factsLine = facts ? `\nPolicy facts: ${JSON.stringify(facts)}` : "";
	return { text: `Accepted\n${lines.join("\n")}${factsLine}`, ok: true };
}
