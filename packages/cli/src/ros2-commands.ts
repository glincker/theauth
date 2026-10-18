import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { stderr, stdout } from "node:process";
import type { RoboticsPermission } from "@glinr/theauth/robotics";
import { loadCredential } from "./auth/token-cache.js";
import { resolveServer } from "./auth-commands.js";

export const ROS2_HELP = `
theauth ros2

Usage:
  theauth ros2 export --robot <agent-id> --enclave <path> --out <dir> [options]
  theauth ros2 export --permissions <file.json> --enclave <path> --out <dir> [options]
  theauth ros2 diff <before.json> <after.json> [--gated omit|include] [--json]

export writes policy.xml (SROS2 policy 0.2.0), permissions.xml and governance.xml
(DDS Security 1.1) and theauth-export.json (what was gated or skipped). The XML is
NOT signed. Sign it with the permissions CA of your keystore, see docs/robotics-ros2.

Permissions come from the robot's agent on a server (--robot, needs theauth login as
an admin) or from a JSON file (--permissions): an array of permissions, or an object
with a "permissions" array.

Options:
  --robot <id>          Agent id of the robot
  --permissions <file>  Read permissions from a file instead of a server
  --server <url>        theAuth server (or THEAUTH_URL)
  --enclave <path>      Enclave path, for example /fleet/robot1/nav
  --out <dir>           Output directory (created if missing)
  --domain <n>          DDS domain id (default 0)
  --not-before <iso>    Grant validity start (default now)
  --not-after <iso>     Grant validity end (default 365 days from now)
  --subject <dn>        Certificate subject (default CN=<enclave>)
  --node <name>         Node name in policy.xml (default last enclave token)
  --gated <mode>        omit (default) or include: what to do with permissions that
                        carry constraints DDS cannot enforce
  --protection <kind>   encrypt (default) or sign, for governance.xml
  --no-ros-discovery    Do not add ros_discovery_info (needed by Fast DDS, Cyclone DDS, Connext)
  --json                Machine readable output
`;

export interface Ros2Args {
	sub?: "export" | "diff";
	robot?: string;
	permissions?: string;
	server?: string;
	enclave?: string;
	out?: string;
	domain?: number;
	notBefore?: string;
	notAfter?: string;
	subject?: string;
	node?: string;
	gated: "omit" | "include";
	protection: "encrypt" | "sign";
	rosDiscovery: boolean;
	files: string[];
	json: boolean;
	help: boolean;
	error: string | null;
}

export function parseRos2Args(args: string[]): Ros2Args {
	const out: Ros2Args = {
		gated: "omit",
		protection: "encrypt",
		rosDiscovery: true,
		files: [],
		json: false,
		help: false,
		error: null,
	};
	const [sub, ...rest] = args;
	if (sub === undefined || sub === "--help" || sub === "-h" || sub === "help") {
		out.help = true;
		return out;
	}
	if (sub !== "export" && sub !== "diff") {
		out.error = `Unknown ros2 command: ${sub}`;
		return out;
	}
	out.sub = sub;
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] ?? "";
		const eq = a.indexOf("=");
		const flag = a.startsWith("--") && eq !== -1 ? a.slice(0, eq) : a;
		const inline = a.startsWith("--") && eq !== -1 ? a.slice(eq + 1) : undefined;
		const value = (): string | undefined => inline ?? rest[++i];
		if (flag === "--robot") out.robot = value();
		else if (flag === "--permissions") out.permissions = value();
		else if (flag === "--server") out.server = value();
		else if (flag === "--enclave") out.enclave = value();
		else if (flag === "--out") out.out = value();
		else if (flag === "--not-before") out.notBefore = value();
		else if (flag === "--not-after") out.notAfter = value();
		else if (flag === "--subject") out.subject = value();
		else if (flag === "--node") out.node = value();
		else if (flag === "--domain") {
			const n = Number(value());
			if (Number.isInteger(n)) out.domain = n;
			else out.error ??= "--domain needs an integer";
		} else if (flag === "--gated") {
			const v = value();
			if (v === "omit" || v === "include") out.gated = v;
			else out.error ??= "--gated must be omit or include";
		} else if (flag === "--protection") {
			const v = value();
			if (v === "encrypt" || v === "sign") out.protection = v;
			else out.error ??= "--protection must be encrypt or sign";
		} else if (flag === "--no-ros-discovery") out.rosDiscovery = false;
		else if (flag === "--json") out.json = true;
		else if (flag === "--help" || flag === "-h") out.help = true;
		else if (!a.startsWith("-") && sub === "diff") out.files.push(a);
		else out.error ??= `Unknown argument: ${a}`;
	}
	if (out.help || out.error !== null) return out;
	if (sub === "diff") {
		if (out.files.length !== 2) out.error = "diff needs two permission files: <before> <after>";
		return out;
	}
	if (!out.enclave) out.error = "Missing --enclave <path>";
	else if (!out.out) out.error = "Missing --out <dir>";
	else if (!out.robot && !out.permissions)
		out.error = "Give --robot <agent-id> or --permissions <file>";
	else if (out.robot && out.permissions) out.error = "Use --robot or --permissions, not both";
	return out;
}

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Accepts an array, `{ permissions }` or the HTTP envelope `{ data: { permissions } }`. */
export function extractPermissions(raw: unknown): RoboticsPermission[] {
	let list: unknown = raw;
	if (isRecord(list) && isRecord(list.data)) list = list.data;
	if (isRecord(list) && "permissions" in list) list = list.permissions;
	if (!Array.isArray(list)) throw new Error("Expected an array of permissions");
	return list.map((p, i): RoboticsPermission => {
		if (!isRecord(p) || typeof p.resource !== "string" || !Array.isArray(p.actions)) {
			throw new Error(`Permission ${i + 1} needs a string "resource" and an "actions" array`);
		}
		if (!p.actions.every((a) => typeof a === "string")) {
			throw new Error(`Permission ${i + 1} has a non string action`);
		}
		return {
			resource: p.resource,
			actions: p.actions as string[],
			constraints: isRecord(p.constraints) ? p.constraints : undefined,
		};
	});
}

async function readPermissionsFile(file: string): Promise<RoboticsPermission[]> {
	const text = await readFile(resolve(file), "utf-8");
	try {
		return extractPermissions(JSON.parse(text));
	} catch (err) {
		if (err instanceof SyntaxError) throw new Error(`Invalid JSON in ${file}: ${err.message}`);
		throw err;
	}
}

async function fetchRobotPermissions(args: Ros2Args): Promise<RoboticsPermission[]> {
	const server = await resolveServer(args.server, false);
	const cred = await loadCredential(server);
	if (!cred) throw new Error(`Not logged in to ${server}. Run: theauth login --server ${server}`);
	const res = await fetch(`${server}/agents/${encodeURIComponent(args.robot ?? "")}`, {
		headers: { authorization: `${cred.tokenType} ${cred.accessToken}` },
	});
	if (res.status === 404) throw new Error(`No agent with id ${args.robot}`);
	if (res.status === 401) throw new Error("Your session is not valid. Run: theauth login");
	if (res.status === 403) throw new Error("Admin access required to read an agent.");
	if (!res.ok) throw new Error(`Server error (${res.status})`);
	return extractPermissions(await res.json());
}

const DAY_MS = 86_400_000;
const DEFAULT_VALIDITY_DAYS = 365;

export async function runRos2Export(args: Ros2Args): Promise<number> {
	try {
		const lib = await import("@glinr/theauth/robotics");
		const permissions = args.permissions
			? await readPermissionsFile(args.permissions)
			: await fetchRobotPermissions(args);
		const now = new Date();
		const result = lib.exportRos2(permissions, {
			robotId: args.robot,
			enclave: args.enclave ?? "",
			subjectName: args.subject,
			domainId: args.domain,
			notBefore: args.notBefore ?? now,
			notAfter: args.notAfter ?? new Date(now.getTime() + DEFAULT_VALIDITY_DAYS * DAY_MS),
			rosDiscoveryTopic: args.rosDiscovery,
			protection: args.protection,
			node: args.node,
			gated: args.gated,
		});
		const dir = resolve(args.out ?? "");
		await mkdir(dir, { recursive: true });
		const written: string[] = [];
		for (const [name, content] of Object.entries(result.files)) {
			await writeFile(join(dir, name), content, "utf-8");
			written.push(join(dir, name));
		}
		const { rules, gated, skipped } = result.policy;
		if (args.json) {
			stdout.write(
				`${JSON.stringify({ written, rules: rules.length, gated, skipped }, null, 2)}\n`,
			);
			return 0;
		}
		stdout.write(`Wrote ${written.length} files to ${dir}\n`);
		stdout.write(
			`${rules.length} rules exported, ${gated.length} gated, ${skipped.length} skipped.\n`,
		);
		for (const g of gated) {
			const what = args.gated === "include" ? "granted statically" : "left out";
			stdout.write(
				`  gated  ${g.resource} [${g.actions.join(",")}] ${what}: ${g.constraints.join(", ")}\n`,
			);
		}
		for (const s of skipped) {
			stdout.write(`  skip   ${s.resource} [${s.actions.join(",")}]: ${s.reason}\n`);
		}
		stdout.write(
			"\nThe XML is unsigned. Next, in your keystore (see docs/robotics-ros2):\n" +
				`  ros2 security create_permission <keystore> ${args.enclave} ${join(dir, "policy.xml")}\n`,
		);
		return 0;
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		if (args.json) stdout.write(`${JSON.stringify({ error: message })}\n`);
		else stderr.write(`theauth ros2 export: ${message}\n`);
		return 1;
	}
}

/** Exit code 0 when the two policies export identically, 2 when they differ, 1 on error. */
export async function runRos2Diff(args: Ros2Args): Promise<number> {
	try {
		const lib = await import("@glinr/theauth/robotics");
		const [before, after] = await Promise.all(args.files.map(readPermissionsFile));
		const diff = lib.diffRosPolicies(before ?? [], after ?? [], { gated: args.gated });
		if (args.json) {
			stdout.write(`${JSON.stringify(diff, null, 2)}\n`);
			return diff.empty ? 0 : 2;
		}
		if (diff.empty) {
			stdout.write("No change in the exported policy.\n");
			return 0;
		}
		const show = (label: string, d: { added: string[]; removed: string[] }): void => {
			for (const x of d.added) stdout.write(`+ ${label} ${x}\n`);
			for (const x of d.removed) stdout.write(`- ${label} ${x}\n`);
		};
		show("publish", diff.publish);
		show("subscribe", diff.subscribe);
		show("gated", diff.gated);
		return 2;
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		if (args.json) stdout.write(`${JSON.stringify({ error: message })}\n`);
		else stderr.write(`theauth ros2 diff: ${message}\n`);
		return 1;
	}
}

export async function runRos2Command(args: string[]): Promise<void> {
	const parsed = parseRos2Args(args);
	if (parsed.help) {
		stdout.write(ROS2_HELP);
		return;
	}
	if (parsed.error) {
		stderr.write(`${parsed.error}\n${ROS2_HELP}`);
		process.exit(1);
	}
	process.exit(parsed.sub === "diff" ? await runRos2Diff(parsed) : await runRos2Export(parsed));
}
