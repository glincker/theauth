import { Eye, EyeOff, ShieldCheck } from "lucide-react";
import { useState } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface LoginProps {
	apiUrl: string;
	onAuthenticated: (secret: string) => void;
}

// ─── Login Screen ─────────────────────────────────────────────────────────────

export function LoginScreen({ apiUrl, onAuthenticated }: LoginProps) {
	const [secret, setSecret] = useState("");
	const [showSecret, setShowSecret] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(false);

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!secret.trim()) return;

		setLoading(true);
		setError(null);

		try {
			const url = `${apiUrl.replace(/\/$/, "")}/api/dashboard/auth`;
			const res = await fetch(url, {
				headers: { Authorization: `Bearer ${secret}` },
			});

			if (res.ok) {
				sessionStorage.setItem("theauth_dashboard_secret", secret);
				onAuthenticated(secret);
			} else {
				setError("Invalid secret. Check your THEAUTH_DASHBOARD_SECRET.");
			}
		} catch {
			setError("Could not reach the API. Make sure the server is running.");
		} finally {
			setLoading(false);
		}
	}

	return (
		<div className="min-h-screen bg-white dark:bg-zinc-950 flex items-center justify-center px-4">
			<div className="w-full max-w-sm">
				{/* Logo */}
				<div className="flex flex-col items-center mb-8">
					<div className="w-12 h-12 rounded-2xl flex items-center justify-center mb-4 bg-gradient-to-br from-yellow-500/20 to-yellow-700/10 border border-yellow-600/30">
						<ShieldCheck className="w-6 h-6 text-yellow-500" strokeWidth={2} />
					</div>
					<h1 className="text-lg font-semibold text-zinc-900 dark:text-white tracking-tight">
						TheAuth
					</h1>
					<p className="text-xs text-zinc-500 uppercase tracking-widest mt-0.5 font-medium">
						Admin Dashboard
					</p>
				</div>

				{/* Card */}
				<div className="bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 shadow-xl shadow-black/40">
					<h2 className="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">
						Dashboard access
					</h2>
					<p className="text-xs text-zinc-500 mb-5">Enter the dashboard secret to continue.</p>

					<form onSubmit={handleSubmit} className="space-y-4">
						{/* Secret field */}
						<div>
							<label
								htmlFor="theauth-secret"
								className="block text-xs font-medium text-zinc-400 mb-1.5"
							>
								Secret
							</label>
							<div className="relative">
								<input
									id="theauth-secret"
									type={showSecret ? "text" : "password"}
									value={secret}
									onChange={(e) => setSecret(e.target.value)}
									placeholder="Enter your dashboard secret"
									autoComplete="current-password"
									className="w-full bg-white dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-zinc-900 dark:text-white placeholder-zinc-600 pr-10 focus:outline-none focus:border-yellow-600/60 focus:ring-1 focus:ring-yellow-600/20 transition-colors"
								/>
								<button
									type="button"
									onClick={() => setShowSecret((v) => !v)}
									className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors"
									aria-label={showSecret ? "Hide secret" : "Show secret"}
								>
									{showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
								</button>
							</div>
						</div>

						{/* Error */}
						{error && (
							<p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
								{error}
							</p>
						)}

						{/* Submit */}
						<button
							type="submit"
							disabled={loading || !secret.trim()}
							className="w-full py-2.5 px-4 rounded-lg text-sm font-medium transition-all duration-100 bg-gradient-to-r from-yellow-600 to-yellow-700 text-zinc-950 hover:from-yellow-500 hover:to-yellow-600 disabled:opacity-40 disabled:cursor-not-allowed shadow-sm"
						>
							{loading ? "Verifying..." : "Access dashboard"}
						</button>
					</form>
				</div>

				<p className="text-center text-xs text-zinc-600 mt-5">
					Set <code className="text-zinc-500 font-mono">THEAUTH_DASHBOARD_SECRET</code> to protect
					this dashboard.
				</p>
			</div>
		</div>
	);
}
