import {
	Activity,
	Bot,
	ChevronRight,
	GitBranch,
	LayoutDashboard,
	Moon,
	ScrollText,
	Server,
	Settings,
	ShieldAlert,
	ShieldCheck,
	Sun,
	Users,
} from "lucide-react";
import type { ReactNode } from "react";
import type { Page, Theme } from "../types.js";
import { DemoBanner } from "./demo-banner.js";

// ─── Types ────────────────────────────────────────────────────────────────────

interface NavItem {
	id: Page;
	label: string;
	icon: typeof Bot;
	description: string;
}

interface SidebarProps {
	currentPage: Page;
	onNavigate: (page: Page) => void;
}

interface LayoutProps {
	currentPage: Page;
	onNavigate: (page: Page) => void;
	children: ReactNode;
	headerActions?: ReactNode;
	demo?: boolean;
	theme: Theme;
	onThemeToggle: () => void;
}

// ─── Nav Config ───────────────────────────────────────────────────────────────

const NAV_ITEMS: NavItem[] = [
	{
		id: "overview",
		label: "Overview",
		icon: LayoutDashboard,
		description: "System overview",
	},
	{
		id: "agents",
		label: "Agents",
		icon: Bot,
		description: "Manage agent identities",
	},
	{
		id: "users",
		label: "Users",
		icon: Users,
		description: "Users who own agents",
	},
	{
		id: "permissions",
		label: "Permissions",
		icon: ShieldCheck,
		description: "Permission templates",
	},
	{
		id: "delegations",
		label: "Delegations",
		icon: GitBranch,
		description: "Agent delegation chains",
	},
	{
		id: "mcp-servers",
		label: "MCP Servers",
		icon: Server,
		description: "Registered MCP servers",
	},
	{
		id: "audit",
		label: "Audit Log",
		icon: ScrollText,
		description: "Immutable audit trail",
	},
	{
		id: "security",
		label: "Security",
		icon: ShieldAlert,
		description: "Security overview",
	},
	{
		id: "settings",
		label: "Settings",
		icon: Settings,
		description: "System configuration",
	},
];

// ─── Logo ─────────────────────────────────────────────────────────────────────

function KavachLogo() {
	return (
		<div className="flex items-center gap-2.5 px-4 py-5 border-b border-zinc-200 dark:border-zinc-800 dark:border-zinc-800">
			<div className="w-7 h-7 rounded-lg bg-amber-600 flex items-center justify-center flex-shrink-0">
				<ShieldCheck className="w-4 h-4 text-white" strokeWidth={2.5} />
			</div>
			<div>
				<div className="text-sm font-semibold text-zinc-900 dark:text-white tracking-tight">
					KavachOS
				</div>
				<div className="text-[10px] text-zinc-500 uppercase tracking-widest font-medium">Admin</div>
			</div>
		</div>
	);
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────

export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
	return (
		<aside className="w-56 flex-shrink-0 bg-white dark:bg-zinc-950 border-r border-zinc-200 dark:border-zinc-800 flex flex-col h-screen sticky top-0">
			<KavachLogo />

			<nav className="flex-1 px-3 py-4 space-y-0.5">
				{NAV_ITEMS.map((item) => {
					const Icon = item.icon;
					const isActive = currentPage === item.id;

					return (
						<button
							key={item.id}
							type="button"
							onClick={() => onNavigate(item.id)}
							className={[
								"w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-100",
								isActive
									? "bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-white"
									: "text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-900",
							].join(" ")}
						>
							<Icon
								className={[
									"w-4 h-4 flex-shrink-0",
									isActive ? "text-amber-500 dark:text-amber-400" : "text-current",
								].join(" ")}
								strokeWidth={isActive ? 2.5 : 2}
							/>
							<span className="text-sm font-medium">{item.label}</span>
							{isActive && (
								<ChevronRight className="w-3 h-3 ml-auto text-zinc-400 dark:text-zinc-600" />
							)}
						</button>
					);
				})}
			</nav>

			{/* Footer status indicator */}
			<div className="px-4 py-4 border-t border-zinc-200 dark:border-zinc-800">
				<div className="flex items-center gap-2 text-xs text-zinc-500">
					<Activity className="w-3.5 h-3.5 text-emerald-500" />
					<span>System Online</span>
				</div>
			</div>
		</aside>
	);
}

// ─── Theme Toggle ─────────────────────────────────────────────────────────────

export function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
	const isDark = theme === "dark";

	return (
		<button
			type="button"
			onClick={onToggle}
			className="w-8 h-8 flex items-center justify-center rounded-lg text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
			aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
		>
			{isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
		</button>
	);
}

// ─── Page Header ──────────────────────────────────────────────────────────────

interface PageHeaderProps {
	title: string;
	description?: string;
	actions?: ReactNode;
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
	return (
		<div className="flex items-start justify-between mb-6">
			<div>
				<h1 className="text-xl font-semibold text-zinc-900 dark:text-white tracking-tight">
					{title}
				</h1>
				{description && (
					<p className="text-sm text-zinc-500 dark:text-zinc-400 mt-0.5">{description}</p>
				)}
			</div>
			{actions && <div className="flex items-center gap-2">{actions}</div>}
		</div>
	);
}

// ─── Main Layout ──────────────────────────────────────────────────────────────

export function Layout({
	currentPage,
	onNavigate,
	children,
	headerActions,
	demo,
	theme,
	onThemeToggle,
}: LayoutProps) {
	return (
		<div className="flex min-h-screen bg-zinc-50 dark:bg-zinc-900 text-zinc-900 dark:text-white">
			<Sidebar currentPage={currentPage} onNavigate={onNavigate} />
			<div className="flex-1 flex flex-col overflow-hidden">
				{demo && <DemoBanner />}
				<header className="flex items-center justify-end px-6 py-3 border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900">
					<div className="flex items-center gap-2">
						<ThemeToggle theme={theme} onToggle={onThemeToggle} />
						{headerActions}
					</div>
				</header>
				<main className="flex-1 overflow-auto">
					<div className="max-w-6xl mx-auto px-6 py-8">{children}</div>
				</main>
			</div>
		</div>
	);
}
