import { spawn } from "node:child_process";
import { stdout } from "node:process";
import { loginWithDeviceFlow } from "./auth/device-flow.js";
import { clearCredential, listServers, loadCredential, serverKey } from "./auth/token-cache.js";

export const AUTH_HELP = `
theauth login | logout | whoami

Usage:
  theauth login  [--server <url>] [--client-id <id>] [--no-browser]
  theauth logout [--server <url>]
  theauth whoami [--server <url>]

--server is the URL where TheAuth is mounted (default: $THEAUTH_URL, else the
only server you are logged in to). Credentials are stored in a 0600 file
(see THEAUTH_CREDENTIALS_FILE).
`;

export interface AuthArgs {
	server?: string;
	clientId?: string;
	noBrowser: boolean;
	help: boolean;
	unknown: string | null;
}

export function parseAuthArgs(args: string[]): AuthArgs {
	const out: AuthArgs = { noBrowser: false, help: false, unknown: null };
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const [flag, inline] = a.split("=", 2);
		const value = () => inline ?? args[++i];
		if (flag === "--server") out.server = value();
		else if (flag === "--client-id") out.clientId = value();
		else if (a === "--no-browser") out.noBrowser = true;
		else if (a === "--help" || a === "-h") out.help = true;
		else out.unknown ??= a;
	}
	return out;
}

async function resolveServer(explicit: string | undefined, required: boolean): Promise<string> {
	const given = explicit ?? process.env.THEAUTH_URL;
	if (given) return serverKey(given);
	const saved = await listServers();
	if (saved.length === 1 && saved[0]) return saved[0];
	throw new Error(
		required || saved.length === 0
			? "No server given. Pass --server <url> or set THEAUTH_URL."
			: `Logged in to several servers (${saved.join(", ")}). Pass --server <url>.`,
	);
}

function openInBrowser(url: string): void {
	if (!/^https?:\/\//.test(url)) return;
	const platform = process.platform;
	const [cmd, cmdArgs]: [string, string[]] =
		platform === "darwin"
			? ["open", [url]]
			: platform === "win32"
				? ["cmd", ["/c", "start", "", url]]
				: ["xdg-open", [url]];
	const child = spawn(cmd, cmdArgs, { stdio: "ignore", detached: true });
	child.on("error", () => {});
	child.unref();
}

export async function runLogin(args: AuthArgs): Promise<number> {
	const serverUrl = await resolveServer(args.server, true);
	const result = await loginWithDeviceFlow({
		serverUrl,
		clientId: args.clientId ?? "theauth-cli",
		openBrowser: args.noBrowser ? undefined : openInBrowser,
	});
	stdout.write(`Logged in to ${serverUrl}${result.userId ? ` as ${result.userId}` : ""}.\n`);
	return 0;
}

export async function runLogout(args: AuthArgs): Promise<number> {
	const serverUrl = await resolveServer(args.server, false);
	const cred = await loadCredential(serverUrl);
	if (cred) {
		// Best effort: revoke the session server side, then drop it locally either way.
		try {
			await fetch(`${serverUrl}/auth/sign-out`, {
				method: "POST",
				headers: { authorization: `${cred.tokenType} ${cred.accessToken}` },
			});
		} catch {
			// Offline logout still clears the local token.
		}
	}
	const removed = await clearCredential(serverUrl);
	stdout.write(removed ? `Logged out of ${serverUrl}.\n` : `Not logged in to ${serverUrl}.\n`);
	return 0;
}

export async function runWhoami(args: AuthArgs): Promise<number> {
	const serverUrl = await resolveServer(args.server, false);
	const cred = await loadCredential(serverUrl);
	if (!cred) {
		stdout.write(`Not logged in to ${serverUrl}. Run: theauth login --server ${serverUrl}\n`);
		return 1;
	}
	const res = await fetch(`${serverUrl}/auth/session`, {
		headers: { authorization: `${cred.tokenType} ${cred.accessToken}` },
	});
	if (res.status === 401) {
		await clearCredential(serverUrl);
		stdout.write("Your session is no longer valid. Run: theauth login\n");
		return 1;
	}
	if (!res.ok) {
		stdout.write(`Server error (${res.status}).\n`);
		return 1;
	}
	const body = (await res.json()) as { user?: { id: string; email?: string; name?: string } };
	const u = body.user;
	stdout.write(`${u?.email ?? u?.name ?? u?.id ?? "unknown user"} (${serverUrl})\n`);
	return 0;
}
