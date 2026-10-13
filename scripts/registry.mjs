// Builds a shadcn-compatible registry from the @glinr/theauth-ui source.
// Items are flat files meant to be copied into an app and owned by it, so
// relative imports are rewritten to sit side by side in one folder.
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SCHEMA = "https://ui.shadcn.com/schema/registry-item.json";

/** Where the committed registry is served from. shadcn tools resolve dependencies by URL. */
export const REGISTRY_URL = "https://raw.githubusercontent.com/glincker/theauth/main/registry";
const dep = (name) => `${REGISTRY_URL}/${name}.json`;

const BASE_FILES = [
	["types.ts", "types.ts"],
	["utils.ts", "utils.ts"],
	["components/defaults.tsx", "defaults.tsx"],
	["components/auth-card.tsx", "auth-card.tsx"],
];

const COMPONENTS = [
	{
		name: "oauth-buttons",
		title: "OAuth buttons",
		description: "Social provider buttons.",
		needs: [],
	},
	{
		name: "sign-in",
		title: "Sign in",
		description: "Email and password sign in with optional OAuth, magic link and passkey.",
		needs: ["oauth-buttons"],
	},
	{
		name: "sign-up",
		title: "Sign up",
		description: "Account creation form with optional OAuth.",
		needs: ["oauth-buttons"],
	},
	{
		name: "forgot-password",
		title: "Forgot password",
		description: "Password reset request form.",
		needs: [],
	},
	{
		name: "two-factor-verify",
		title: "Two-factor verify",
		description: "One-time code entry with backup code fallback.",
		needs: [],
	},
	{
		name: "user-button",
		title: "User button",
		description: "Avatar menu with sign out.",
		needs: [],
	},
];

/** `../types.js` and `./x.js` become `./types` and `./x`. */
function flattenImports(source) {
	return source.replace(/(from\s+["'])(?:\.\.?\/)+(?:[a-z-]+\/)*([a-z-]+)\.js(["'])/g, "$1./$2$3");
}

function npmDependencies(source) {
	const found = new Set();
	for (const m of source.matchAll(/from\s+["']([^."'][^"']*)["']/g)) {
		const spec = m[1];
		if (spec === "react") continue;
		found.add(spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0]);
	}
	return [...found].sort();
}

function file(uiSrc, from, to) {
	const content = flattenImports(readFileSync(join(uiSrc, from), "utf8"));
	const type = to.endsWith(".tsx") ? "registry:component" : "registry:lib";
	return { path: `theauth/${to}`, type, target: `components/theauth/${to}`, content };
}

/** Registry items for the sign-in UI. `uiSrc` is packages/ui/src. */
export function buildRegistry(uiSrc) {
	const baseFiles = BASE_FILES.map(([from, to]) => file(uiSrc, from, to));
	const items = [
		{
			$schema: SCHEMA,
			name: "theauth-base",
			type: "registry:component",
			title: "theAuth base",
			description:
				"Shared types, class helper, default slots and the auth card used by every theAuth component.",
			dependencies: npmDependencies(baseFiles.map((f) => f.content).join("\n")),
			files: baseFiles,
		},
	];
	for (const c of COMPONENTS) {
		const f = file(uiSrc, `components/${c.name}.tsx`, `${c.name}.tsx`);
		items.push({
			$schema: SCHEMA,
			name: c.name,
			type: "registry:component",
			title: c.title,
			description: c.description,
			dependencies: npmDependencies(f.content),
			registryDependencies: ["theauth-base", ...c.needs].map(dep),
			files: [f],
		});
	}
	return items;
}

/** The index shadcn tools read: `registry.json`. */
export function registryIndex(items) {
	return {
		$schema: "https://ui.shadcn.com/schema/registry.json",
		name: "theauth",
		homepage: "https://docs.theauth.dev/ui-components",
		items: items.map(({ files, ...rest }) => ({
			...rest,
			files: files.map(({ content, ...f }) => f),
		})),
	};
}
