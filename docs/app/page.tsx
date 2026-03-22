import type { ReactNode } from "react";
import {
	Shield,
	ArrowRight,
	Terminal,
	Key,
	GitBranch,
	FileText,
	Server,
	AlertTriangle,
	TrendingUp,
	Cpu,
	DollarSign,
	Bot,
	Check,
	X,
	Minus,
	ChevronRight,
	Lock,
} from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/button";
import { Footer } from "@/components/footer";
import { NavSpacer } from "@/components/nav";
import { InteractiveGrid } from "@/components/interactive-grid";
import {
	HonoIcon,
	ExpressIcon,
	NextjsIcon,
	FastifyIcon,
	NuxtIcon,
	SvelteIcon,
	AstroIcon,
} from "@/components/icons";

export default function HomePage() {
	return (
		<div className="relative text-fd-foreground">
			<NavSpacer />

			{/* ===== 1. HERO ===== */}
			<section className="relative overflow-hidden border-b border-fd-border">
				{/* Gold ambient glow */}
				<div className="pointer-events-none absolute bottom-0 left-1/2 h-[500px] w-[800px] -translate-x-1/2 translate-y-1/2 rounded-full bg-[var(--kavach-gold-mid)]/[0.05] blur-3xl" />
				{/* Grid background */}
				<div className="absolute inset-0 z-0 overflow-hidden">
					<InteractiveGrid />
				</div>

				<div className="relative z-10 mx-auto max-w-5xl px-6 py-20 sm:px-10 sm:py-28">
					{/* Badge */}
					<div className="mb-8 flex animate-fade-in justify-center">
						<Link
							href="/docs"
							className="group inline-flex items-center gap-1.5 rounded-full border border-[var(--kavach-gold-mid)]/25 bg-[var(--kavach-gold-mid)]/8 px-4 py-1.5 text-[11px] font-medium text-[var(--kavach-gold-deep)] transition-colors hover:bg-[var(--kavach-gold-mid)]/15 dark:text-[var(--kavach-gold-bright)]"
						>
							<Shield className="h-3 w-3" />
							Open source · TypeScript · MIT
							<ChevronRight className="h-3 w-3 opacity-40 transition-transform group-hover:translate-x-0.5" />
						</Link>
					</div>

					{/* Headline */}
					<div className="animate-fade-up text-center">
						<h1 className="font-heading text-4xl font-extrabold tracking-tight text-lift sm:text-5xl xl:text-6xl xl:leading-[1.1]">
							Auth for AI agents.
						</h1>
						<p className="mx-auto mt-5 max-w-xl text-base font-light text-fd-muted-foreground/70 leading-relaxed sm:text-lg">
							Give every agent a cryptographic identity, scoped permissions, and
							an audit trail. Ships in 5 minutes, works with your existing stack.
						</p>
					</div>

					{/* CTAs */}
					<div className="animate-fade-up-delay-1 mt-8 flex flex-wrap items-center justify-center gap-3">
						<Button href="/docs/quickstart" variant="gold" size="lg">
							Get started
							<ArrowRight className="h-4 w-4" />
						</Button>
						<Button
							href="https://github.com/kavachos/kavachos"
							variant="outline"
							size="lg"
							external
						>
							View on GitHub
						</Button>
					</div>

					{/* Install command */}
					<div className="animate-fade-up-delay-2 mt-6 flex justify-center">
						<code className="inline-flex items-center gap-2 rounded-lg border border-fd-border bg-fd-card/80 px-4 py-2.5 font-mono text-sm text-fd-muted-foreground/60 backdrop-blur-sm">
							<Terminal className="h-3.5 w-3.5 text-[var(--kavach-gold-deep)] dark:text-[var(--kavach-gold-primary)]" />
							pnpm add kavachos
						</code>
					</div>

					{/* Code snippet */}
					<div className="animate-fade-up-delay-3 mx-auto mt-12 max-w-2xl">
						<HeroCode />
					</div>
				</div>
			</section>

			{/* ===== 2. PROBLEM STATEMENT ===== */}
			<section className="border-b border-fd-border bg-fd-secondary/20">
				<div className="mx-auto max-w-5xl px-6 py-16 sm:px-10 sm:py-20">
					<p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-fd-muted-foreground/40">
						Why now
					</p>
					<h2 className="font-heading text-2xl font-bold tracking-tight text-lift sm:text-3xl">
						Agents are shipping.{" "}
						<span className="gradient-gold-text text-lift-gold">Auth is not.</span>
					</h2>
					<p className="mt-4 max-w-2xl text-sm font-light text-fd-muted-foreground/60 leading-relaxed">
						Non-human identities now outnumber humans 100 to 1 in most
						enterprise environments. Most teams deploying agents have not gone
						through a security review. Regulations are catching up.
					</p>

					<div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-3">
						<StatCard
							number="41%"
							label="of MCP servers have zero auth"
							source="Bitsight 2025"
						/>
						<StatCard
							number="81%"
							label="of teams deploy agents before security approval"
							source="CISA 2025"
						/>
						<StatCard
							number="100:1"
							label="non-human identities vs human identities"
							source="CyberArk 2025"
						/>
					</div>

					<div className="mt-6 rounded-lg border border-amber-500/20 bg-amber-500/5 px-5 py-4">
						<div className="flex items-start gap-3">
							<AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
							<p className="text-sm text-fd-muted-foreground/70 leading-relaxed">
								<span className="font-semibold text-fd-foreground">
									EU AI Act enforcement starts August 2, 2026.
								</span>{" "}
								Article 12 requires audit logs for high-risk AI systems. Article
								9 mandates access control. Organizations without agent auth
								infrastructure will not be compliant.
							</p>
						</div>
					</div>
				</div>
			</section>

			{/* ===== 3. FEATURE GRID ===== */}
			<section className="border-b border-fd-border">
				<div className="mx-auto max-w-5xl px-6 pt-16 sm:px-10 sm:pt-20">
					<p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-fd-muted-foreground/40">
						Features
					</p>
					<h2 className="font-heading text-2xl font-bold tracking-tight text-lift sm:text-3xl">
						Everything agent auth needs
					</h2>
					<p className="mt-3 max-w-xl text-sm font-light text-fd-muted-foreground/60 leading-relaxed">
						Built agent-first. Not adapted from human auth.
					</p>
				</div>

				<div className="mx-auto mt-10 max-w-5xl">
					<div className="grid grid-cols-1 divide-y divide-fd-border border-t border-fd-border sm:grid-cols-2 sm:divide-x lg:grid-cols-3">
						<FeatureBlock
							num="01"
							icon={Key}
							title="Agent identity"
							description="Bearer tokens with SHA-256 hashing, shown once on creation, rotatable on demand. Each agent is a first-class identity with metadata and expiry."
						/>
						<FeatureBlock
							num="02"
							icon={Shield}
							title="Permission engine"
							description="Resource patterns with wildcards (mcp:github:*), five constraint types including rate limits, time windows, and IP allowlists."
						/>
						<FeatureBlock
							num="03"
							icon={GitBranch}
							title="Delegation chains"
							description="Orchestrators pass a strict subset of their permissions to sub-agents. Configurable depth limits and expiry prevent privilege escalation."
						/>
						<FeatureBlock
							num="04"
							icon={FileText}
							title="Audit trail"
							description="Every authorization decision logged with agent ID, action, resource, outcome, and timestamp. Export to CSV or JSON for compliance reporting."
						/>
						<FeatureBlock
							num="05"
							icon={Server}
							title="MCP OAuth 2.1"
							description="Full authorization server for the Model Context Protocol. PKCE S256, RFC 9728, RFC 8414, RFC 7591, RFC 8707 — complete spec coverage."
						/>
						<FeatureBlock
							num="06"
							icon={Lock}
							title="Compliance reports"
							description="Pre-built reports for EU AI Act Article 12, NIST AI RMF, SOC 2 Type II, and ISO 42001. One command to generate an audit package."
						/>
						<FeatureBlock
							num="07"
							icon={AlertTriangle}
							title="Anomaly detection"
							description="Flags high-frequency requests, denial spikes, off-hours activity, and escalation attempts. Configurable thresholds, webhook alerts."
						/>
						<FeatureBlock
							num="08"
							icon={TrendingUp}
							title="Trust scoring"
							description="Graduated autonomy based on observed behavior. Agents earn higher trust levels over time, unlocking expanded permissions without manual review."
						/>
						<FeatureBlock
							num="09"
							icon={Bot}
							title="Agent discovery"
							description="Structured capability cards for agent-to-agent interoperability. Agents can advertise what they do and query what others can do."
						/>
						<FeatureBlock
							num="10"
							icon={DollarSign}
							title="Budget policies"
							description="Token cost caps per agent, per day, or per task. Auto-throttle when budgets are approached. Hard stops at the limit."
						/>
						<FeatureBlock
							num="11"
							icon={Cpu}
							title="Framework adapters"
							description="Core has zero framework dependencies. First-class adapters for Hono, Express, Next.js, Fastify, Nuxt, SvelteKit, and Astro."
						/>
						<FeatureBlock
							num="12"
							icon={GitBranch}
							title="Auto-migration"
							description="Schema migrations run automatically on startup. Supports SQLite, PostgreSQL, and MySQL. No manual SQL, no manual rollbacks."
						/>
					</div>
				</div>
			</section>

			{/* ===== 4. HOW IT WORKS ===== */}
			<section className="border-b border-fd-border bg-fd-secondary/20">
				<div className="mx-auto max-w-5xl px-6 py-16 sm:px-10 sm:py-20">
					<p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-fd-muted-foreground/40">
						How it works
					</p>
					<h2 className="font-heading text-2xl font-bold tracking-tight text-lift sm:text-3xl">
						Three steps to protected agents
					</h2>

					<div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-3">
						<Step
							number="1"
							title="Install and init"
							code={`import { createKavach } from 'kavachos';\n\nconst kavach = createKavach({\n  database: { provider: 'sqlite',\n    url: './kavach.db' },\n});`}
						/>
						<Step
							number="2"
							title="Create an agent"
							code={`const agent = await kavach.agent.create({\n  ownerId: 'user-123',\n  name: 'github-reader',\n  permissions: [{\n    resource: 'mcp:github:*',\n    actions: ['read'],\n  }],\n});`}
						/>
						<Step
							number="3"
							title="Authorize actions"
							code={`const result = await kavach.authorize(\n  agent.id,\n  { action: 'read',\n    resource: 'mcp:github:repos' },\n);\n\nresult.allowed; // true`}
						/>
					</div>
				</div>
			</section>

			{/* ===== 5. FRAMEWORK SUPPORT ===== */}
			<section className="border-b border-fd-border">
				<div className="mx-auto max-w-5xl px-6 py-14 sm:px-10">
					<p className="mb-6 text-center text-[10px] font-semibold uppercase tracking-[0.2em] text-fd-muted-foreground/40">
						Works with your framework
					</p>
					<div className="flex flex-wrap items-center justify-center gap-3">
						<FrameworkPill icon={HonoIcon} name="Hono" />
						<FrameworkPill icon={ExpressIcon} name="Express" />
						<FrameworkPill icon={NextjsIcon} name="Next.js" />
						<FrameworkPill icon={FastifyIcon} name="Fastify" />
						<FrameworkPill icon={NuxtIcon} name="Nuxt" />
						<FrameworkPill icon={SvelteIcon} name="SvelteKit" />
						<FrameworkPill icon={AstroIcon} name="Astro" />
					</div>
					<p className="mt-6 text-center text-xs text-fd-muted-foreground/40">
						Core has zero framework dependencies. Use it with any Node.js or
						Bun runtime.
					</p>
				</div>
			</section>

			{/* ===== 6. COMPARISON TABLE ===== */}
			<section className="border-b border-fd-border bg-fd-secondary/20">
				<div className="mx-auto max-w-5xl px-6 py-16 sm:px-10 sm:py-20">
					<p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-fd-muted-foreground/40">
						Comparison
					</p>
					<h2 className="font-heading text-2xl font-bold tracking-tight text-lift sm:text-3xl">
						Built for agents, not adapted from user auth
					</h2>
					<p className="mt-3 max-w-xl text-sm font-light text-fd-muted-foreground/60 leading-relaxed">
						General-purpose auth libraries cover human login flows well. Agent
						auth is a different problem.
					</p>

					<div className="mt-10 overflow-x-auto rounded-lg border border-fd-border">
						<table className="w-full text-sm">
							<thead>
								<tr className="border-b border-fd-border bg-fd-secondary/50">
									<th className="px-5 py-3.5 text-left text-xs font-medium text-fd-muted-foreground/60">
										Feature
									</th>
									<th className="px-5 py-3.5 text-center text-xs font-semibold gradient-gold-text">
										KavachOS
									</th>
									<th className="px-5 py-3.5 text-center text-xs font-medium text-fd-muted-foreground/60">
										better-auth
									</th>
									<th className="px-5 py-3.5 text-center text-xs font-medium text-fd-muted-foreground/60">
										Auth0 Agents
									</th>
									<th className="px-5 py-3.5 text-center text-xs font-medium text-fd-muted-foreground/60">
										Roll your own
									</th>
								</tr>
							</thead>
							<tbody className="divide-y divide-fd-border">
								<CompRow
									feature="Agent-first data model"
									kv
									ba={false}
									a0="partial"
									diy={false}
								/>
								<CompRow
									feature="MCP OAuth 2.1"
									kv
									ba={false}
									a0={false}
									diy={false}
								/>
								<CompRow
									feature="Delegation chains"
									kv
									ba={false}
									a0={false}
									diy={false}
								/>
								<CompRow
									feature="Compliance reports"
									kv
									ba={false}
									a0="partial"
									diy={false}
								/>
								<CompRow
									feature="Anomaly detection"
									kv
									ba={false}
									a0="partial"
									diy={false}
								/>
								<CompRow
									feature="Trust scoring"
									kv
									ba={false}
									a0={false}
									diy={false}
								/>
								<CompRow
									feature="Open source"
									kv
									ba
									a0={false}
									diy
								/>
								<CompRow
									feature="npm install"
									kv
									ba
									a0={false}
									diy
								/>
							</tbody>
						</table>
					</div>
				</div>
			</section>

			{/* ===== 7. COMPLIANCE ===== */}
			<section className="border-b border-fd-border">
				<div className="mx-auto max-w-5xl px-6 py-16 sm:px-10 sm:py-20">
					<p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-fd-muted-foreground/40">
						Compliance
					</p>
					<div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:gap-16">
						<div className="lg:w-1/2">
							<h2 className="font-heading text-2xl font-bold tracking-tight text-lift sm:text-3xl">
								Regulation is coming.
								<br />
								<span className="gradient-gold-text text-lift-gold">
									Be ready.
								</span>
							</h2>
							<p className="mt-4 text-sm font-light text-fd-muted-foreground/60 leading-relaxed">
								The EU AI Act begins enforcement on August 2, 2026. Article 12
								requires audit logs for every high-risk AI system decision.
								Article 9 mandates access control. KavachOS generates the
								evidence packages you need.
							</p>
							<div className="mt-6 inline-flex items-center gap-2.5 rounded-lg border border-amber-500/25 bg-amber-500/8 px-4 py-3">
								<AlertTriangle className="h-4 w-4 shrink-0 text-amber-500" />
								<p className="text-xs font-medium text-amber-600 dark:text-amber-400">
									EU AI Act enforcement: August 2, 2026
								</p>
							</div>
						</div>

						<div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:w-1/2">
							<ComplianceCard
								name="EU AI Act"
								articles="Art. 9, 12, 72"
								description="Access control, audit logging, and transparency requirements for high-risk AI systems."
							/>
							<ComplianceCard
								name="NIST AI RMF"
								articles="Govern 1.1, Map 5.2"
								description="Risk governance framework with traceable decision records and accountability chains."
							/>
							<ComplianceCard
								name="SOC 2 Type II"
								articles="CC6.1, CC6.3"
								description="Logical access controls and monitoring evidence for annual SOC 2 audits."
							/>
							<ComplianceCard
								name="ISO 42001"
								articles="§ 6.1, 8.4"
								description="AI management system standard covering risk treatment and operational controls."
							/>
						</div>
					</div>
				</div>
			</section>

			{/* ===== 8. CTA ===== */}
			<section className="relative overflow-hidden border-b border-fd-border">
				<div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--kavach-gold-mid)/4%_0%,_transparent_70%)]" />
				<div className="relative mx-auto max-w-5xl px-6 py-20 text-center sm:px-10 sm:py-28">
					<h2 className="font-heading text-3xl font-bold tracking-tight text-lift sm:text-4xl">
						Start in 5 minutes
					</h2>
					<p className="mx-auto mt-4 max-w-md text-sm font-light text-fd-muted-foreground/60 leading-relaxed">
						TypeScript, MIT licensed, works with any auth provider. No account
						needed.
					</p>

					<div className="mt-8 flex justify-center">
						<code className="inline-flex items-center gap-2 rounded-lg border border-fd-border bg-fd-card px-5 py-3 font-mono text-sm text-fd-muted-foreground/60">
							<Terminal className="h-4 w-4 text-[var(--kavach-gold-deep)] dark:text-[var(--kavach-gold-primary)]" />
							pnpm add kavachos
						</code>
					</div>

					<div className="mt-6 flex flex-wrap items-center justify-center gap-3">
						<Button href="/docs/quickstart" variant="gold" size="lg">
							Read the docs
							<ArrowRight className="h-4 w-4" />
						</Button>
						<Button
							href="https://github.com/kavachos/kavachos"
							variant="outline"
							size="lg"
							external
						>
							Star on GitHub
						</Button>
					</div>

					<p className="mt-8 text-xs text-fd-muted-foreground/30 italic">
						kavach (कवच) — armor. From the Mahabharata: Karna&apos;s divine
						golden shield.
					</p>
				</div>
			</section>

			<Footer />
		</div>
	);
}

/* ===== Section components ===== */

function HeroCode() {
	return (
		<div className="overflow-hidden rounded-xl border border-fd-border bg-fd-card shadow-2xl shadow-black/20">
			{/* Window chrome */}
			<div className="flex items-center gap-1.5 border-b border-fd-border bg-fd-secondary/50 px-4 py-3">
				<div className="h-2.5 w-2.5 rounded-full bg-fd-border" />
				<div className="h-2.5 w-2.5 rounded-full bg-fd-border" />
				<div className="h-2.5 w-2.5 rounded-full bg-fd-border" />
				<span className="ml-3 font-mono text-[11px] text-fd-muted-foreground/40">
					quickstart.ts
				</span>
			</div>
			<pre className="overflow-x-auto p-5 text-[13px] leading-relaxed">
				<code className="font-mono">
					<CodeLine>
						<Kw>import</Kw> {"{ createKavach }"} <Kw>from</Kw>{" "}
						<Str>&apos;kavachos&apos;</Str>;
					</CodeLine>
					<CodeLine>&nbsp;</CodeLine>
					<CodeLine>
						<Kw>const</Kw> kavach = <Fn>createKavach</Fn>
						{"({ database: { provider: "}
						<Str>&apos;sqlite&apos;</Str>
						{", url: "}
						<Str>&apos;./kavach.db&apos;</Str>
						{" } });"}
					</CodeLine>
					<CodeLine>&nbsp;</CodeLine>
					<CodeLine>
						<Kw>const</Kw> agent = <Kw>await</Kw> kavach.agent.
						<Fn>create</Fn>
						{"({"}
					</CodeLine>
					<CodeLine>
						{"  "}name: <Str>&apos;github-reader&apos;</Str>,
					</CodeLine>
					<CodeLine>
						{"  "}permissions: [{"{ resource: "}
						<Str>&apos;mcp:github:*&apos;</Str>
						{", actions: ["}
						<Str>&apos;read&apos;</Str>
						{"] }"}],
					</CodeLine>
					<CodeLine>{"});"}</CodeLine>
					<CodeLine>&nbsp;</CodeLine>
					<CodeLine>
						<Kw>const</Kw> {"{ allowed }"} = <Kw>await</Kw> kavach.
						<Fn>authorize</Fn>
						{"(agent.id, {"}
					</CodeLine>
					<CodeLine>
						{"  "}action: <Str>&apos;read&apos;</Str>, resource:{" "}
						<Str>&apos;mcp:github:repos&apos;</Str>,
					</CodeLine>
					<CodeLine>
						{"});"}{" "}
						<Cm>// allowed: true — audit log entry created</Cm>
					</CodeLine>
				</code>
			</pre>
		</div>
	);
}

function CodeLine({ children }: { children: ReactNode }) {
	return <div className="leading-relaxed">{children}</div>;
}

function Kw({ children }: { children: ReactNode }) {
	return <span className="text-purple-400">{children}</span>;
}

function Str({ children }: { children: ReactNode }) {
	return <span className="text-emerald-400">{children}</span>;
}

function Fn({ children }: { children: ReactNode }) {
	return <span className="text-amber-300">{children}</span>;
}

function Cm({ children }: { children: ReactNode }) {
	return (
		<span className="text-fd-muted-foreground/50 italic">{children}</span>
	);
}

function StatCard({
	number,
	label,
	source,
}: {
	number: string;
	label: string;
	source: string;
}) {
	return (
		<div className="rounded-xl border border-fd-border bg-fd-card p-5 transition-colors hover:border-[var(--kavach-gold-mid)]/20">
			<p className="font-heading text-3xl font-bold tracking-tight gradient-gold-text">
				{number}
			</p>
			<p className="mt-2 text-[13px] font-light text-fd-muted-foreground/60 leading-snug">
				{label}
			</p>
			<p className="mt-3 font-mono text-[9px] text-fd-muted-foreground/30">
				{source}
			</p>
		</div>
	);
}

function FeatureBlock({
	num,
	icon: Icon,
	title,
	description,
}: {
	num: string;
	icon: typeof Key;
	title: string;
	description: string;
}) {
	return (
		<div className="group border-b border-fd-border p-6 transition-colors hover:bg-fd-accent/20 sm:p-8">
			<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-fd-muted-foreground/30">
				<span className="text-[var(--kavach-gold-deep)] dark:text-[var(--kavach-gold-primary)]">
					{num}
				</span>{" "}
				{title}
			</p>
			<div className="mt-3 inline-flex rounded-md border border-[var(--kavach-gold-mid)]/15 bg-[var(--kavach-gold-mid)]/5 p-2 transition-colors group-hover:border-[var(--kavach-gold-mid)]/30 group-hover:bg-[var(--kavach-gold-mid)]/10">
				<Icon className="h-4 w-4 text-[var(--kavach-gold-deep)] dark:text-[var(--kavach-gold-primary)]" />
			</div>
			<p className="mt-3 text-[13px] font-light text-fd-muted-foreground/60 leading-relaxed">
				{description}
			</p>
		</div>
	);
}

function Step({
	number,
	title,
	code,
}: {
	number: string;
	title: string;
	code: string;
}) {
	return (
		<div className="flex flex-col gap-4">
			<div className="flex items-center gap-3">
				<div className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[var(--kavach-gold-mid)]/15 font-heading text-sm font-bold text-[var(--kavach-gold-deep)] dark:text-[var(--kavach-gold-primary)]">
					{number}
				</div>
				<h3 className="font-heading text-base font-semibold">{title}</h3>
			</div>
			<div className="overflow-hidden rounded-lg border border-fd-border bg-fd-card">
				<pre className="overflow-x-auto p-4 text-[12px] leading-relaxed">
					<code className="font-mono text-fd-muted-foreground/70">{code}</code>
				</pre>
			</div>
		</div>
	);
}

function FrameworkPill({
	icon: Icon,
	name,
}: {
	icon: typeof HonoIcon;
	name: string;
}) {
	return (
		<span className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-fd-border/60 bg-fd-card px-4 py-2.5 text-sm font-medium text-fd-muted-foreground/60 transition-colors hover:border-[var(--kavach-gold-mid)]/20 hover:text-fd-foreground">
			<Icon className="h-4 w-4" />
			{name}
		</span>
	);
}

type CellValue = boolean | "partial";

function CompRow({
	feature,
	kv,
	ba,
	a0,
	diy,
}: {
	feature: string;
	kv?: CellValue;
	ba?: CellValue;
	a0?: CellValue;
	diy?: CellValue;
}) {
	return (
		<tr className="text-xs">
			<td className="px-5 py-3 font-medium text-fd-foreground/80">{feature}</td>
			<td className="px-5 py-3 text-center">
				<Cell value={kv} />
			</td>
			<td className="px-5 py-3 text-center">
				<Cell value={ba} />
			</td>
			<td className="px-5 py-3 text-center">
				<Cell value={a0} />
			</td>
			<td className="px-5 py-3 text-center">
				<Cell value={diy} />
			</td>
		</tr>
	);
}

function Cell({ value }: { value?: CellValue }) {
	if (value === true)
		return (
			<Check className="mx-auto h-4 w-4 text-emerald-500 dark:text-emerald-400" />
		);
	if (value === "partial")
		return (
			<span className="inline-flex items-center gap-1 text-amber-500">
				<Minus className="h-3.5 w-3.5" />
				<span className="text-[10px]">partial</span>
			</span>
		);
	return (
		<X className="mx-auto h-4 w-4 text-fd-muted-foreground/25" />
	);
}

function ComplianceCard({
	name,
	articles,
	description,
}: {
	name: string;
	articles: string;
	description: string;
}) {
	return (
		<div className="rounded-lg border border-fd-border bg-fd-card p-4 transition-colors hover:border-[var(--kavach-gold-mid)]/20">
			<div className="flex items-start justify-between gap-2">
				<p className="font-heading text-sm font-semibold">{name}</p>
				<span className="shrink-0 rounded-md border border-fd-border bg-fd-secondary/50 px-2 py-0.5 font-mono text-[9px] text-fd-muted-foreground/40">
					{articles}
				</span>
			</div>
			<p className="mt-2 text-[12px] font-light text-fd-muted-foreground/60 leading-relaxed">
				{description}
			</p>
		</div>
	);
}
