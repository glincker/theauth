import { execFileSync } from "node:child_process";
import { cpus, platform, release, totalmem } from "node:os";

export function hardware() {
	const list = cpus();
	let commit = process.env.GITHUB_SHA ?? null;
	if (!commit) {
		try {
			commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
		} catch {
			commit = null;
		}
	}
	return {
		nodeVersion: process.version,
		cpuModel: list[0]?.model ?? "unknown",
		cpuCount: list.length,
		memoryGb: Math.round((totalmem() / 1024 ** 3) * 10) / 10,
		platform: `${platform()} ${release()}`,
		commit,
		ci: process.env.CI === "true",
		gcExposed: typeof globalThis.gc === "function",
	};
}
