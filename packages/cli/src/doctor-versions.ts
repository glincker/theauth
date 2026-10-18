// Semver range checks for the core version against adapter peer ranges (no dependencies).

type Triple = [number, number, number];

function parseVersion(v: string): Triple | null {
	const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(v.trim());
	if (!m) return null;
	return [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
}

function compare(a: Triple, b: Triple): number {
	for (let i = 0; i < 3; i++) {
		const d = (a[i] as number) - (b[i] as number);
		if (d !== 0) return d;
	}
	return 0;
}

function satisfiesComparator(version: Triple, comparator: string): boolean {
	const m = /^(>=|<=|>|<|=|\^|~)?\s*(.+)$/.exec(comparator.trim());
	if (!m) return true;
	const target = parseVersion(m[2] as string);
	if (!target) return true;
	const op = m[1] ?? "=";
	const c = compare(version, target);
	if (op === ">=") return c >= 0;
	if (op === ">") return c > 0;
	if (op === "<=") return c <= 0;
	if (op === "<") return c < 0;
	if (op === "^") {
		const upper: Triple =
			target[0] > 0
				? [target[0] + 1, 0, 0]
				: target[1] > 0
					? [0, target[1] + 1, 0]
					: [0, 0, target[2] + 1];
		return c >= 0 && compare(version, upper) < 0;
	}
	if (op === "~") return c >= 0 && compare(version, [target[0], target[1] + 1, 0]) < 0;
	return c === 0;
}

/** Small semver range check: space separated comparators, `||` alternatives, `^`, `~`, `x`. Unknown syntax passes. */
export function satisfiesRange(version: string, range: string): boolean {
	const v = parseVersion(version);
	if (!v) return true;
	return range.split("||").some((alt) => {
		const text = alt.trim();
		if (text === "" || text === "*" || /^[xX*]$/.test(text)) return true;
		return text
			.split(/\s+/)
			.filter((c) => c !== "")
			.every((c) => satisfiesComparator(v, c.replace(/\.[xX*]/g, ".0")));
	});
}
