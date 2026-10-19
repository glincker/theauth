import { resolve } from "node:path";
import { stderr, stdout } from "node:process";
import { pathToFileURL } from "node:url";
import type { TheAuth } from "@glinr/theauth";
import { ATTEST_HELP, parseAttestArgs, runAttest } from "./device-attest-command.js";
import { parseSpiffeArgs, runSpiffeVerify, SPIFFE_HELP } from "./device-spiffe-command.js";

export const DEVICE_HELP = `
theauth device

Usage:
  theauth device register --owner <userId> --name <name> [--kind sensor] [--hardware-id SN]
                          [--group g]... [--perm "mqtt:sensors:*=publish"]... [--psk]
  theauth device list [--owner <userId>] [--status active|suspended|revoked] [--group g]
  theauth device suspend <deviceId> [--reason text]
  theauth device resume <deviceId>
  theauth device revoke <deviceId> [--reason text]
  theauth device enroll-token --owner <userId> --kind claim|bulk [--max-uses n] [--ttl seconds]
                              [--group g]... [--perm "resource=action,action"]...
  theauth device attest android|apple|tpm --evidence <file> --nonce <n> ...
                                (offline evidence check, no --config; see "device attest --help")
  theauth device spiffe verify-x509|verify-jwt|link ...
                                (SPIFFE SVID check and device mapping; see "device spiffe --help")

Every command needs --config <file.mjs>: an ES module whose default export is a
TheAuth instance (or a config object) with \`devices\` and \`agents\` configured.
Secrets (PSKs, claim codes, bulk tokens) are printed once and never stored in plain text.

Options:
  --config <file>  Instance or config module
  --json           Machine readable output
`;

type Sub = "register" | "list" | "suspend" | "resume" | "revoke" | "enroll-token";
const SUBS: readonly Sub[] = ["register", "list", "suspend", "resume", "revoke", "enroll-token"];

export interface DeviceArgs {
	sub?: Sub;
	id?: string;
	config?: string;
	owner?: string;
	name?: string;
	kind?: string;
	hardwareId?: string;
	status?: "active" | "suspended" | "revoked";
	groups: string[];
	perms: Array<{ resource: string; actions: string[] }>;
	psk: boolean;
	reason?: string;
	tokenKind?: "claim" | "bulk";
	maxUses?: number;
	ttl?: number;
	json: boolean;
	help: boolean;
	error: string | null;
}

/** `resource=action,action`. The last `=` splits, so resources keep their colons and stars. */
export function parsePerm(value: string): { resource: string; actions: string[] } | null {
	const at = value.lastIndexOf("=");
	if (at <= 0) return null;
	const resource = value.slice(0, at).trim();
	const actions = value
		.slice(at + 1)
		.split(",")
		.map((a) => a.trim())
		.filter(Boolean);
	return resource && actions.length > 0 ? { resource, actions } : null;
}

export function parseDeviceArgs(args: string[]): DeviceArgs {
	const out: DeviceArgs = {
		groups: [],
		perms: [],
		psk: false,
		json: false,
		help: false,
		error: null,
	};
	const [sub, ...rest] = args;
	if (sub === undefined || sub === "--help" || sub === "-h" || sub === "help") {
		out.help = true;
		return out;
	}
	if (!(SUBS as readonly string[]).includes(sub)) {
		out.error = `Unknown device command: ${sub}`;
		return out;
	}
	out.sub = sub as Sub;
	const value = (i: number): string | undefined => rest[i + 1];
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] ?? "";
		switch (a) {
			case "--json":
				out.json = true;
				break;
			case "--help":
			case "-h":
				out.help = true;
				break;
			case "--psk":
				out.psk = true;
				break;
			case "--config":
				out.config = value(i);
				i++;
				break;
			case "--owner":
				out.owner = value(i);
				i++;
				break;
			case "--name":
				out.name = value(i);
				i++;
				break;
			case "--kind": {
				const v = value(i);
				i++;
				if (out.sub === "enroll-token") {
					if (v === "claim" || v === "bulk") out.tokenKind = v;
					else out.error ??= "--kind must be claim or bulk";
				} else out.kind = v;
				break;
			}
			case "--hardware-id":
				out.hardwareId = value(i);
				i++;
				break;
			case "--group": {
				const v = value(i);
				i++;
				if (v) out.groups.push(v);
				break;
			}
			case "--perm": {
				const p = parsePerm(value(i) ?? "");
				i++;
				if (p) out.perms.push(p);
				else out.error ??= '--perm needs "resource=action[,action]"';
				break;
			}
			case "--status": {
				const v = value(i);
				i++;
				if (v === "active" || v === "suspended" || v === "revoked") out.status = v;
				else out.error ??= "--status must be active, suspended or revoked";
				break;
			}
			case "--reason":
				out.reason = value(i);
				i++;
				break;
			case "--max-uses":
			case "--ttl": {
				const n = Number(value(i));
				i++;
				if (!Number.isInteger(n) || n <= 0) out.error ??= `${a} needs a positive integer`;
				else if (a === "--ttl") out.ttl = n;
				else out.maxUses = n;
				break;
			}
			default:
				if (a.startsWith("-")) out.error ??= `Unknown argument: ${a}`;
				else if (out.id === undefined) out.id = a;
				else out.error ??= `Unexpected argument: ${a}`;
		}
	}
	if (out.help || out.error) return out;
	if (!out.config) out.error = "Missing --config <file.mjs>";
	else if (out.sub === "register" && (!out.owner || !out.name))
		out.error = "register needs --owner and --name";
	else if (["suspend", "resume", "revoke"].includes(out.sub) && !out.id)
		out.error = `${out.sub} needs a device id`;
	else if (out.sub === "enroll-token" && (!out.owner || !out.tokenKind)) {
		out.error = "enroll-token needs --owner and --kind claim|bulk";
	}
	return out;
}

type Devices = NonNullable<TheAuth["device"]>;

/** Load the default export of the config module: a TheAuth instance, or a config passed to createTheAuth. */
export async function loadDevices(file: string): Promise<Devices> {
	const mod = (await import(pathToFileURL(resolve(file)).href)) as Record<string, unknown>;
	const loaded = mod.default ?? mod.theauth ?? mod.config;
	let auth: TheAuth;
	if (typeof loaded === "object" && loaded !== null && "authorize" in loaded) {
		auth = loaded as TheAuth;
	} else if (typeof loaded === "object" && loaded !== null) {
		const { createTheAuth } = await import("@glinr/theauth");
		auth = await createTheAuth(loaded as Parameters<typeof createTheAuth>[0]);
	} else {
		throw new Error(`${file} must default export a TheAuth instance or a config object`);
	}
	if (!auth.device)
		throw new Error("devices are not configured: add `devices: {}` (and `agents`) to the config");
	return auth.device;
}

function line(d: {
	id: string;
	name: string;
	status: string;
	ownerId: string;
	groups: string[];
}): string {
	return `${d.id}  ${d.status.padEnd(9)}  ${d.ownerId}  ${d.name}${d.groups.length ? `  [${d.groups.join(", ")}]` : ""}`;
}

/** Run one command against a device module. Returns the text to print. */
export async function runDevice(args: DeviceArgs, devices: Devices): Promise<string> {
	const show = (value: unknown, text: string): string =>
		args.json ? JSON.stringify(value, null, 2) : text;
	switch (args.sub) {
		case "register": {
			const created = await devices.register({
				ownerId: args.owner ?? "",
				name: args.name ?? "",
				...(args.kind && { kind: args.kind }),
				...(args.hardwareId && { hardwareId: args.hardwareId }),
				groups: args.groups,
				permissions: args.perms,
				...(args.psk && { credential: { kind: "psk" as const } }),
			});
			const secret = created.credential?.secret;
			return show(
				created,
				`${line(created.device)}${secret ? `\nPSK (shown once): ${secret}` : ""}`,
			);
		}
		case "list": {
			const list = await devices.list({
				...(args.owner && { ownerId: args.owner }),
				...(args.status && { status: args.status }),
				...(args.groups[0] && { group: args.groups[0] }),
			});
			return show(list, list.length ? list.map(line).join("\n") : "No devices");
		}
		case "suspend":
			return show(await devices.suspend(args.id ?? "", args.reason), "Suspended");
		case "resume":
			return show(await devices.resume(args.id ?? ""), "Resumed");
		case "revoke": {
			const result = await devices.revoke(args.id ?? "", args.reason);
			return show(
				result,
				`Revoked (${result.revokedDelegations.length} delegation chains cascaded)`,
			);
		}
		case "enroll-token": {
			const token = await devices.createEnrollmentToken({
				ownerId: args.owner ?? "",
				kind: args.tokenKind ?? "claim",
				...(args.maxUses !== undefined && { maxUses: args.maxUses }),
				...(args.ttl !== undefined && { ttlSeconds: args.ttl }),
				groups: args.groups,
				permissions: args.perms,
			});
			return show(
				token,
				`${token.kind} token (shown once): ${token.token}\nid ${token.id}, ${token.maxUses} use(s), expires ${token.expiresAt.toISOString()}`,
			);
		}
		default:
			return DEVICE_HELP;
	}
}

export async function runDeviceCommand(argv: string[]): Promise<void> {
	if (argv[0] === "attest") {
		const rest = argv.slice(1);
		if (rest.length === 0 || rest.includes("--help") || rest.includes("-h")) {
			stdout.write(ATTEST_HELP);
			return;
		}
		const attest = parseAttestArgs(rest);
		if (attest.error) {
			stderr.write(`${attest.error}\n${ATTEST_HELP}`);
			process.exitCode = 1;
			return;
		}
		const done = await runAttest(attest);
		stdout.write(`${done.text}\n`);
		if (!done.ok) process.exitCode = 1;
		return;
	}
	if (argv[0] === "spiffe") {
		const rest = argv.slice(1);
		if (rest.length === 0 || rest.includes("--help") || rest.includes("-h")) {
			stdout.write(SPIFFE_HELP);
			return;
		}
		const spiffe = parseSpiffeArgs(rest);
		if (spiffe.error) {
			stderr.write(`${spiffe.error}\n${SPIFFE_HELP}`);
			process.exitCode = 1;
			return;
		}
		if (spiffe.sub === "link") {
			const devices = await loadDevices(spiffe.config ?? "");
			const [deviceId, spiffeId] = spiffe.positional as [string, string];
			const credential = await devices.addCredential(deviceId, { kind: "spiffe", spiffeId });
			stdout.write(
				`${spiffe.json ? JSON.stringify(credential, null, 2) : `Linked ${spiffeId} to ${deviceId} (credential ${credential.id})`}\n`,
			);
			return;
		}
		const done = await runSpiffeVerify(spiffe);
		stdout.write(`${done.text}\n`);
		if (!done.ok) process.exitCode = 1;
		return;
	}
	const args = parseDeviceArgs(argv);
	if (args.help) {
		stdout.write(DEVICE_HELP);
		return;
	}
	if (args.error) {
		stderr.write(`${args.error}\n${DEVICE_HELP}`);
		process.exitCode = 1;
		return;
	}
	const devices = await loadDevices(args.config ?? "");
	stdout.write(`${await runDevice(args, devices)}\n`);
}
