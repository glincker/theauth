import { LogOut } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { LoginScreen } from "./login.js";

// Types

interface AuthGateProps {
	apiUrl: string;
	children: (onLogout: () => void) => React.ReactNode;
}

type AuthState = "checking" | "authenticated" | "unauthenticated";

// Helpers

function authUrl(apiUrl: string): string {
	return `${apiUrl.replace(/\/$/, "")}/api/dashboard/auth`;
}

/** Whether the HttpOnly session cookie is still accepted. */
async function hasSession(apiUrl: string): Promise<boolean> {
	try {
		const res = await fetch(authUrl(apiUrl), { credentials: "include" });
		return res.ok;
	} catch {
		return false;
	}
}

// Logout Button

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

// Auth Gate

export function AuthGate({ apiUrl, children }: AuthGateProps) {
	const [state, setState] = useState<AuthState>("checking");

	const logout = useCallback(() => {
		void fetch(authUrl(apiUrl), { method: "DELETE", credentials: "include" })
			.catch(() => undefined)
			.finally(() => setState("unauthenticated"));
	}, [apiUrl]);

	useEffect(() => {
		void hasSession(apiUrl).then((valid) => {
			setState(valid ? "authenticated" : "unauthenticated");
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
