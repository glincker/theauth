import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { createApiClient } from "./api/client.js";
import { AuthGate, LogoutButton } from "./components/auth-gate.js";
import { Layout } from "./components/layout.js";
import { ToastProvider } from "./components/toast.js";
import { AgentsPage } from "./pages/agents.js";
import { AuditPage } from "./pages/audit.js";
import { DelegationsPage } from "./pages/delegations.js";
import { McpServersPage } from "./pages/mcp-servers.js";
import { OverviewPage } from "./pages/overview.js";
import { PermissionsPage } from "./pages/permissions.js";
import { SecurityPage } from "./pages/security.js";
import { SettingsPage } from "./pages/settings.js";
import { UsersPage } from "./pages/users.js";
import type { DashboardProps, Page } from "./types.js";

// ─── Query Client (module-scoped singleton for library mode) ──────────────────

const defaultQueryClient = new QueryClient({
	defaultOptions: {
		queries: {
			staleTime: 30_000,
			retry: 1,
			refetchOnWindowFocus: false,
		},
	},
});

// ─── Inner Dashboard (requires QueryClientProvider above) ─────────────────────

interface InnerDashboardProps {
	apiUrl: string;
	onLogout: () => void;
	demo?: boolean;
	theme: "light" | "dark";
	onThemeToggle: () => void;
}

function InnerDashboard({ apiUrl, onLogout, demo, theme, onThemeToggle }: InnerDashboardProps) {
	const [currentPage, setCurrentPage] = useState<Page>("overview");
	const client = useMemo(() => createApiClient(apiUrl), [apiUrl]);

	function renderPage() {
		switch (currentPage) {
			case "overview":
				return <OverviewPage client={client} onNavigate={setCurrentPage} />;
			case "agents":
				return <AgentsPage client={client} />;
			case "users":
				return <UsersPage client={client} onNavigate={setCurrentPage} />;
			case "audit":
				return <AuditPage client={client} />;
			case "permissions":
				return <PermissionsPage client={client} />;
			case "delegations":
				return <DelegationsPage client={client} />;
			case "mcp-servers":
				return <McpServersPage client={client} />;
			case "security":
				return <SecurityPage client={client} />;
			case "settings":
				return <SettingsPage client={client} />;
		}
	}

	return (
		<Layout
			currentPage={currentPage}
			onNavigate={setCurrentPage}
			headerActions={<LogoutButton onLogout={onLogout} />}
			demo={demo}
			theme={theme}
			onThemeToggle={onThemeToggle}
		>
			{renderPage()}
		</Layout>
	);
}

// ─── Public Component ─────────────────────────────────────────────────────────

const STORAGE_KEY = "kavachos-theme";

function resolveInitialTheme(defaultTheme: "light" | "dark"): "light" | "dark" {
	if (typeof window === "undefined") return defaultTheme;
	const stored = localStorage.getItem(STORAGE_KEY);
	return stored === "light" || stored === "dark" ? stored : defaultTheme;
}

export function KavachDashboard({ apiUrl, theme = "dark", demo }: DashboardProps) {
	const [currentTheme, setCurrentTheme] = useState<"light" | "dark">(() =>
		resolveInitialTheme(theme),
	);

	useEffect(() => {
		const stored = localStorage.getItem(STORAGE_KEY);
		if (stored === null) {
			setCurrentTheme(theme);
		}
	}, [theme]);

	useEffect(() => {
		if (currentTheme === "dark") {
			document.documentElement.classList.add("dark");
		} else {
			document.documentElement.classList.remove("dark");
		}
		localStorage.setItem(STORAGE_KEY, currentTheme);
	}, [currentTheme]);

	return (
		<div data-kavachos-dashboard>
			<AuthGate apiUrl={apiUrl}>
				{(onLogout) => (
					<QueryClientProvider client={defaultQueryClient}>
						<ToastProvider>
							<InnerDashboard
								apiUrl={apiUrl}
								onLogout={onLogout}
								demo={demo}
								theme={currentTheme}
								onThemeToggle={() =>
									setCurrentTheme((current) => (current === "dark" ? "light" : "dark"))
								}
							/>
						</ToastProvider>
					</QueryClientProvider>
				)}
			</AuthGate>
		</div>
	);
}
