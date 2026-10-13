#!/usr/bin/env node
/**
 * Fails when `pnpm audit --prod` reports a high or critical advisory that is
 * not listed in scripts/audit-allowlist.json. Run from the pre-push hook so a
 * vulnerable dependency is caught before CI is.
 *
 * Allowlist entries need a reason and a review date. An entry whose date has
 * passed fails the gate, so exceptions do not outlive their reason.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const BLOCKING = new Set(["high", "critical"]);
const err = (line) => process.stderr.write(`${line}\n`);
const allowlistPath = new URL("./audit-allowlist.json", import.meta.url);

function runAudit() {
	try {
		return execFileSync("pnpm", ["audit", "--prod", "--json"], {
			encoding: "utf8",
			maxBuffer: 64 * 1024 * 1024,
		});
	} catch (failure) {
		// pnpm audit exits non-zero when it finds anything; the JSON is on stdout.
		if (
			failure &&
			typeof failure === "object" &&
			"stdout" in failure &&
			typeof failure.stdout === "string"
		) {
			return failure.stdout;
		}
		throw failure;
	}
}

let report;
try {
	report = JSON.parse(runAudit());
} catch {
	err("audit-gate: could not read `pnpm audit` output. Is the registry reachable?");
	process.exit(2);
}

const allow = JSON.parse(readFileSync(allowlistPath, "utf8")).allow ?? [];
const today = new Date().toISOString().slice(0, 10);
const expired = allow.filter((a) => a.reviewBy && a.reviewBy < today);
const allowed = new Map(allow.map((a) => [a.module, a]));

const failures = [];
for (const advisory of Object.values(report.advisories ?? {})) {
	if (!BLOCKING.has(advisory.severity)) continue;
	if (allowed.has(advisory.module_name)) continue;
	failures.push(advisory);
}

if (expired.length > 0) {
	err("audit-gate: allowlist entries past their review date:");
	for (const a of expired) err(`  ${a.module} (review by ${a.reviewBy}): ${a.reason}`);
}

if (failures.length > 0) {
	err("audit-gate: high or critical advisories in production dependencies:");
	for (const a of failures) {
		const via = a.findings?.[0]?.paths?.[0] ?? "";
		err(
			`  [${a.severity}] ${a.module_name} ${a.vulnerable_versions} (fixed in ${a.patched_versions})`,
		);
		err(`    ${a.title}`);
		if (via) err(`    via ${via}`);
	}
	err("Update the dependency, add a pnpm override, or allowlist it with a reason.");
}

process.exit(failures.length > 0 || expired.length > 0 ? 1 : 0);
