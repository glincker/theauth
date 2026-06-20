import { LogOut } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { LoginScreen } from "./login.js";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AuthGateProps {
	apiUrl: string;
	children: (onLogout: () => void) => React.ReactNode;
}

type AuthState = "checking" | "authenticated" | "unauthenticated";

const SESSION_KEY = "theauth_dashboard_secret";

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function validateSecret(apiUrl: string, secret: string): Promise<boolean> {
	try {
		const url = `${apiUrl.replace(/\/$/, "")}/api/dashboard/auth`;
		const res = await fetch(url, {
			headers: { Authorization: `Bearer ${secret}` },
		});
		return res.ok;
	} catch {
		return false;
	}
}

// ─── Logout Button ────────────────────────────────────────────────────────────

export interface LogoutButtonProps {
	onLogout: () => void;
}

export function LogoutButton({ onLogout }: LogoutButtonProps) {
	return (
		<button
			type="button"
			onClick={onLogout}
			className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-all duration-100"
			title="Sign out"
		>
			<LogOut className="w-3.5 h-3.5" />
			<span>Sign out</span>
		</button>
	);
}

// ─── Auth Gate ────────────────────────────────────────────────────────────────

export function AuthGate({ apiUrl, children }: AuthGateProps) {
	const [state, setState] = useState<AuthState>("checking");

	const logout = useCallback(() => {
		sessionStorage.removeItem(SESSION_KEY);
		setState("unauthenticated");
	}, []);

	useEffect(() => {
		const stored = sessionStorage.getItem(SESSION_KEY);
		if (!stored) {
			setState("unauthenticated");
			return;
		}

		// Validate the stored secret against the API
		void validateSecret(apiUrl, stored).then((valid) => {
			setState(valid ? "authenticated" : "unauthenticated");
			if (!valid) sessionStorage.removeItem(SESSION_KEY);
		});
	}, [apiUrl]);

	if (state === "checking") {
		return (
			<div className="min-h-screen bg-white dark:bg-zinc-950 flex items-center justify-center">
				<div className="w-5 h-5 rounded-full border-2 border-zinc-300 dark:border-zinc-700 border-t-yellow-500 animate-spin" />
			</div>
		);
	}

	if (state === "unauthenticated") {
		return <LoginScreen apiUrl={apiUrl} onAuthenticated={() => setState("authenticated")} />;
	}

	return <>{children(logout)}</>;
}
