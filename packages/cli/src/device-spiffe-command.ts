import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const SPIFFE_HELP = `
theauth device spiffe verify-x509 --cert <chain.pem> (--bundle <bundle.json> | --root <ca.pem>...) [options]
theauth device spiffe verify-jwt  --token <file|-> --bundle <bundle.json> --audience <aud>... [options]
theauth device spiffe link <deviceId> <spiffe-id> --config <file.mjs>

verify-x509 and verify-jwt check an SVID offline with the same code the SPIFFE bridge runs. No config is needed.
Exit code 0 when the SVID is accepted, 1 when it is refused.

  --cert <file>        Leaf certificate first, then intermediates, PEM
  --bundle <file>      SPIFFE bundle (JWK Set with x509-svid and jwt-svid keys), as served by a bundle endpoint
  --root <file>        Trust anchor PEM (repeatable), instead of --bundle, for X.509-SVIDs
  --trust-domain <td>  Trust domain of the bundle or roots (default: taken from the SVID)
  --audience <aud>     Accepted JWT-SVID audience (repeatable)
  --token <file|->     JWT-SVID, a file or - for standard input
  --now <iso time>     Verify as of this time
  --skew <seconds>     Clock skew allowed (default 30)
  --json               Machine readable output

link maps a SPIFFE ID (with a path) to a device, so the bridge resolves that workload to it.
It needs --config <file.mjs>, the same module the other device commands use.
`;

export interface SpiffeArgs {
	sub: "verify-x509" | "verify-jwt" | "link";
	cert?: string;
	bundle?: string;
	roots: string[];
	trustDomain?: string;
	audience: string[];
	token?: string;
	now?: Date;
	skew?: number;
	json: boolean;
	config?: string;
	positional: string[];
	error: string | null;
}

const SUBS = ["verify-x509", "verify-jwt", "link"] as const;

export function parseSpiffeArgs(args: string[]): SpiffeArgs {
	const [sub, ...rest] = args;
	const out: SpiffeArgs = {
		sub: SUBS.find((s) => s === sub) ?? "verify-x509",
		roots: [],
		audience: [],
		json: false,
		positional: [],
		error: null,
	};
	if (!SUBS.some((s) => s === sub)) {
		out.error = `spiffe needs one of: ${SUBS.join(", ")}`;
		return out;
	}
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] as string;
		const value = (): string => {
			const v = rest[++i];
			if (v === undefined) out.error = `${a} needs a value`;
			return v ?? "";
		};
		if (a === "--cert") out.cert = value();
		else if (a === "--bundle") out.bundle = value();
		else if (a === "--root") out.roots.push(value());
		else if (a === "--trust-domain") out.trustDomain = value();
		else if (a === "--audience") out.audience.push(value());
		else if (a === "--token") out.token = value();
		else if (a === "--config") out.config = value();
		else if (a === "--json") out.json = true;
		else if (a === "--now") {
			const d = new Date(value());
			if (Number.isNaN(d.getTime())) out.error = "--now must be an ISO time";
			else out.now = d;
		} else if (a === "--skew") {
			const n = Number(value());
			if (!Number.isInteger(n) || n < 0) out.error = "--skew must be a whole number of seconds";
			else out.skew = n;
		} else if (a.startsWith("--")) out.error = `Unknown option ${a}`;
		else out.positional.push(a);
		if (out.error) return out;
	}
	if (sub === "verify-x509") {
		if (!out.cert) out.error = "verify-x509 needs --cert";
		else if (!out.bundle && out.roots.length === 0) out.error = "Pass --bundle or --root";
	} else if (sub === "verify-jwt") {
		if (!out.token) out.error = "verify-jwt needs --token";
		else if (!out.bundle) out.error = "verify-jwt needs --bundle";
		else if (out.audience.length === 0) out.error = "verify-jwt needs --audience";
	} else if (out.positional.length !== 2) out.error = "link needs <deviceId> <spiffe-id>";
	else if (!out.config) out.error = "link needs --config";
	return out;
}

async function readStdin(): Promise<string> {
	const chunks: Uint8Array[] = [];
	for await (const c of process.stdin) chunks.push(c as Uint8Array);
	return Buffer.concat(chunks).toString("utf8");
}

function describe(result: { ok: boolean }, json: boolean): string {
	if (json) return JSON.stringify(result, null, 2);
	const r = result as
		| { ok: true; identity: Record<string, unknown> }
		| { ok: false; code: string; reason: string };
	if (!r.ok) return `Refused (${r.code}): ${r.reason}`;
	const lines = Object.entries(r.identity).map(
		([k, v]) => `  ${k}: ${v instanceof Date ? v.toISOString() : JSON.stringify(v)}`,
	);
	return `Accepted\n${lines.join("\n")}`;
}

/** Offline verification: builds a one domain bundle store from files and runs the bridge checks. */
export async function runSpiffeVerify(args: SpiffeArgs): Promise<{ text: string; ok: boolean }> {
	const core = await import("@glinr/theauth");
	const bundleText = args.bundle ? await readFile(resolve(args.bundle), "utf8") : undefined;
	const roots = await Promise.all(args.roots.map((f) => readFile(resolve(f), "utf8")));
	const at = args.now ?? new Date();
	let domain = args.trustDomain;
	let subject = "";
	if (args.sub === "verify-x509") subject = await readFile(resolve(args.cert ?? ""), "utf8");
	else
		subject = (
			args.token === "-" ? await readStdin() : await readFile(resolve(args.token ?? ""), "utf8")
		).trim();
	if (!domain) {
		const peek = args.sub === "verify-jwt" ? peekSub(subject) : peekUri(subject);
		const id = peek ? core.parseSpiffeId(peek) : undefined;
		domain = id?.ok ? id.trustDomain : undefined;
	}
	if (!domain)
		return { text: "Could not read a trust domain from the SVID, pass --trust-domain", ok: false };
	const store = core.createBundleStore({
		[domain]:
			bundleText !== undefined
				? { bundle: bundleText, ...(roots.length > 0 && { roots }) }
				: { roots },
	});
	const skew = args.skew !== undefined ? { clockSkewSeconds: args.skew } : {};
	if (args.sub === "verify-jwt") {
		const result = await core.verifyJwtSvid(subject, store, {
			audience: args.audience,
			now: at,
			...skew,
		});
		return { text: describe(result, args.json), ok: result.ok };
	}
	const chain = (
		subject.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []
	).map((pem) => Uint8Array.from(Buffer.from(pem.replace(/-----[A-Z ]+-----|\s+/g, ""), "base64")));
	const result = await core.verifyX509Svid(chain, store, { now: at, ...skew });
	return { text: describe(result, args.json), ok: result.ok };
}

function peekSub(jwt: string): string | undefined {
	try {
		const part = jwt.split(".")[1] ?? "";
		const sub = (JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as { sub?: unknown })
			.sub;
		return typeof sub === "string" ? sub : undefined;
	} catch {
		return undefined;
	}
}

/** First spiffe:// URI that appears as text in the certificate, read from the DER SAN bytes. */
function peekUri(pem: string): string | undefined {
	const first = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/)?.[1];
	if (!first) return undefined;
	const text = Buffer.from(first.replace(/\s+/g, ""), "base64").toString("latin1");
	return text.match(/spiffe:\/\/[\x21-\x7e]+/)?.[0];
}
