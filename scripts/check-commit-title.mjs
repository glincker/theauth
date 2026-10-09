// Validates the first line of a commit message against the same rule CI applies to PR titles
// (.github/workflows/lint-pr.yml): a known type, optional scope, then a subject that starts lowercase.
// Used by the commit-msg git hook: node scripts/check-commit-title.mjs <message-file>
import { readFileSync } from "node:fs";

const TYPES = ["feat", "fix", "perf", "refactor", "docs", "test", "chore"];
const PATTERN = new RegExp(`^(${TYPES.join("|")})(\\([^)]+\\))?!?: (?![A-Z])\\S.*$`);
const SKIP = /^(Merge |Revert "|fixup! |squash! )/;
const DASHES = /[–—]/;

export function checkTitle(title) {
	if (SKIP.test(title)) return null;
	if (!PATTERN.test(title)) {
		return `Commit title must look like "<type>: <lowercase subject>" with type one of ${TYPES.join(", ")}. Example: "fix: handle expired session in agent flow".`;
	}
	if (DASHES.test(title))
		return "Commit title must not contain em or en dashes. Use a comma, colon or period.";
	return null;
}

const file = process.argv[2];
if (file) {
	const title = readFileSync(file, "utf8").split("\n")[0].trim();
	const problem = checkTitle(title);
	if (problem) {
		process.stderr.write(`${problem}\nGot: "${title}"\n`);
		process.exit(1);
	}
}
