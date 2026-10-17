#!/usr/bin/env node
// Opt-in smoke test for a token vault provider preset against the REAL provider.
// It sends ONE refresh_token grant with YOUR test credentials. It is never run
// by CI or by the test suite, and it needs the built core (pnpm build first).
//
// Usage:
//   PROVIDER=github CLIENT_ID=... CLIENT_SECRET=... REFRESH_TOKEN=... \
//     node scripts/smoke-token-vault-presets.mjs
//   PROVIDER=github node scripts/smoke-token-vault-presets.mjs --dry-run
//
// Prints the provider, HTTP status and token metadata. Token values are never
// printed, and failures print the provider's error code only.
// biome-ignore-all lint/suspicious/noConsole: CLI smoke script reports results on stdout and stderr
// biome-ignore-all lint/suspicious/noUndeclaredEnvVars: the env vars are this script's documented inputs
import { providerPresets, resolveProviderPreset } from "../packages/core/dist/index.js";

const DRY_RUN = process.argv.includes("--dry-run");
const TIMEOUT_MS = 15_000;
const SAFE_ERROR_CODE = /^[a-z_]{1,64}$/;
const MASK = "***";

function fail(provider, status, code) {
	console.error(`provider=${provider} status=${status} error=${code}`);
	process.exitCode = 1;
}

/** Mirrors refreshTokens() in packages/core/src/vault/refresh.ts. That function is not exported from the package root. */
function buildRefreshRequest(resolved, refreshToken) {
	const basic = resolved.authStyle === "client_secret_basic";
	const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken });
	const headers = {
		"Content-Type": "application/x-www-form-urlencoded",
		Accept: "application/json",
	};
	if (basic) {
		const pair = `${encodeURIComponent(resolved.clientId)}:${encodeURIComponent(resolved.clientSecret)}`;
		headers.Authorization = `Basic ${btoa(pair)}`;
	} else {
		form.set("client_id", resolved.clientId);
		form.set("client_secret", resolved.clientSecret);
	}
	return { url: resolved.tokenUrl, headers, form, basic };
}

function printDryRun(id, req, authStyle) {
	console.log("dry-run: nothing is sent");
	console.log(`provider: ${id}`);
	console.log(`request: POST ${req.url}`);
	console.log(`auth style: ${authStyle}`);
	console.log(`header names: ${Object.keys(req.headers).join(", ")}`);
	console.log(`body keys: ${[...req.form.keys()].map((k) => `${k}=${MASK}`).join(", ")}`);
}

async function main() {
	const id = process.env.PROVIDER ?? "";
	if (!Object.hasOwn(providerPresets, id)) {
		console.error(
			`Refusing to run: PROVIDER must be a known preset id. Known ids: ${Object.keys(providerPresets).join(", ")}`,
		);
		process.exitCode = 1;
		return;
	}

	const env = {
		CLIENT_ID: process.env.CLIENT_ID ?? "",
		CLIENT_SECRET: process.env.CLIENT_SECRET ?? "",
		REFRESH_TOKEN: process.env.REFRESH_TOKEN ?? "",
	};
	const missing = Object.keys(env).filter((k) => env[k] === "");
	if (missing.length > 0 && !DRY_RUN) {
		console.error(`Missing env vars: ${missing.join(", ")}`);
		process.exitCode = 1;
		return;
	}

	const resolved = resolveProviderPreset(id, {
		clientId: env.CLIENT_ID || MASK,
		clientSecret: env.CLIENT_SECRET || MASK,
	});
	const req = buildRefreshRequest(resolved, env.REFRESH_TOKEN || MASK);

	if (DRY_RUN) {
		printDryRun(id, req, resolved.authStyle);
		return;
	}

	let res;
	try {
		res = await fetch(req.url, {
			method: "POST",
			headers: req.headers,
			body: req.form.toString(),
			signal: AbortSignal.timeout(TIMEOUT_MS),
		});
	} catch {
		fail(id, "none", "network_error");
		return;
	}

	let parsed;
	try {
		parsed = await res.json();
	} catch {
		fail(id, res.status, "non_json_response");
		return;
	}
	const data = parsed !== null && typeof parsed === "object" ? parsed : {};

	if (!res.ok || typeof data.access_token !== "string" || data.access_token === "") {
		const providerCode =
			typeof data.error === "string" && SAFE_ERROR_CODE.test(data.error) ? data.error : null;
		const code = providerCode ?? (res.ok ? "no_access_token" : `http_${res.status}`);
		fail(id, res.status, code);
		return;
	}

	const rotated =
		typeof data.refresh_token === "string" && data.refresh_token !== env.REFRESH_TOKEN;
	console.log(`provider: ${id}`);
	console.log(`http status: ${res.status}`);
	console.log("access_token returned: true");
	console.log(`expires_in: ${typeof data.expires_in === "number" ? data.expires_in : "none"}`);
	console.log(`new refresh_token returned (rotation): ${rotated}`);
	console.log(`scope: ${typeof data.scope === "string" ? data.scope : "(none)"}`);
}

await main();
