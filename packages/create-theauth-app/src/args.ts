export const TEMPLATES = ["first-run", "next-saas", "hono-mcp"] as const;
export type TemplateName = (typeof TEMPLATES)[number];

export interface CliArgs {
	/** Project directory given on the command line, if any. */
	dir: string | null;
	template: TemplateName | null;
	/** Skip the prompts and use defaults for anything not given. */
	yes: boolean;
	install: boolean;
	help: boolean;
	error: string | null;
}

export const HELP = `create-theauth-app: scaffold a theAuth project

Usage:
  npx @glinr/create-theauth-app [dir] [options]

Options:
  --template <name>  ${TEMPLATES.join(", ")} (default: first-run)
  --yes, -y          Use defaults, no prompts
  --no-install       Write files only, do not run the package manager
  --help, -h         Show this help

Quickstart:
  npx @glinr/create-theauth-app my-agent-app --yes && cd my-agent-app && npm start
`;

function isTemplate(value: string): value is TemplateName {
	return (TEMPLATES as readonly string[]).includes(value);
}

export function parseArgs(argv: string[]): CliArgs {
	const out: CliArgs = {
		dir: null,
		template: null,
		yes: false,
		install: true,
		help: false,
		error: null,
	};
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i] ?? "";
		if (arg === "--yes" || arg === "-y") out.yes = true;
		else if (arg === "--no-install") out.install = false;
		else if (arg === "--help" || arg === "-h") out.help = true;
		else if (arg === "--template" || arg.startsWith("--template=")) {
			const value = arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : (argv[++i] ?? "");
			if (isTemplate(value)) out.template = value;
			else out.error = `Unknown template "${value}". Choose one of: ${TEMPLATES.join(", ")}`;
		} else if (arg.startsWith("-")) out.error = `Unknown option: ${arg}`;
		else if (out.dir === null) out.dir = arg;
		else out.error = `Unexpected argument: ${arg}`;
	}
	return out;
}
