"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const API = "/api/theauth";

export default function Home() {
	const router = useRouter();
	const [mode, setMode] = useState<"signin" | "signup">("signin");
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [name, setName] = useState("");
	const [error, setError] = useState("");
	const [success, setSuccess] = useState("");
	const [loading, setLoading] = useState(false);

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		setError("");
		setSuccess("");
		setLoading(true);

		try {
			const endpoint = mode === "signin" ? `${API}/auth/sign-in` : `${API}/auth/sign-up`;
			const body = mode === "signin"
				? { email, password }
				: { email, password, name: name || undefined };

			const res = await fetch(endpoint, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});

			const data = await res.json();

			if (!res.ok) {
				setError(data.error?.message ?? data.message ?? `Failed (${res.status})`);
				return;
			}

			if (mode === "signup") {
				const verifyToken = data.token ?? data.verificationToken;
				if (verifyToken) {
					setSuccess(`Account created! Verify: http://localhost:3003/verify?token=${verifyToken}`);
				} else {
					setSuccess("Account created! You can sign in now.");
				}
				setMode("signin");
			} else {
				// Store session token and redirect
				if (data.session?.token) {
					localStorage.setItem("theauth_session", data.session.token);
				}
				router.push("/dashboard");
			}
		} catch (err) {
			setError(err instanceof Error ? err.message : "Network error");
		} finally {
			setLoading(false);
		}
	}

	return (
		<div className="min-h-screen flex items-center justify-center bg-zinc-950">
			<div className="w-full max-w-sm mx-auto p-6">
				<div className="text-center mb-8">
					<h1 className="text-2xl font-bold text-white">TheAuth Demo</h1>
					<p className="text-zinc-500 text-sm mt-1">Auth OS for AI agents and humans</p>
				</div>

				<div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
					{/* Tabs */}
					<div className="flex mb-6 border-b border-zinc-800">
						<button
							type="button"
							onClick={() => { setMode("signin"); setError(""); setSuccess(""); }}
							className={`flex-1 pb-3 text-sm font-medium border-b-2 transition-colors ${
								mode === "signin"
									? "border-amber-500 text-white"
									: "border-transparent text-zinc-500 hover:text-zinc-300"
							}`}
						>
							Sign in
						</button>
						<button
							type="button"
							onClick={() => { setMode("signup"); setError(""); setSuccess(""); }}
							className={`flex-1 pb-3 text-sm font-medium border-b-2 transition-colors ${
								mode === "signup"
									? "border-amber-500 text-white"
									: "border-transparent text-zinc-500 hover:text-zinc-300"
							}`}
						>
							Sign up
						</button>
					</div>

					<form onSubmit={handleSubmit} className="space-y-4">
						{mode === "signup" && (
							<input
								type="text"
								placeholder="Name"
								value={name}
								onChange={(e) => setName(e.target.value)}
								className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-amber-600"
							/>
						)}
						<input
							type="email"
							placeholder="Email"
							value={email}
							onChange={(e) => setEmail(e.target.value)}
							required
							className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-amber-600"
						/>
						<input
							type="password"
							placeholder="Password (min 8 chars)"
							value={password}
							onChange={(e) => setPassword(e.target.value)}
							required
							minLength={8}
							className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-amber-600"
						/>
						<button
							type="submit"
							disabled={loading}
							className="w-full bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white font-medium rounded-lg px-4 py-2.5 text-sm transition-colors"
						>
							{loading ? "..." : mode === "signin" ? "Sign in" : "Create account"}
						</button>
					</form>

					{error && (
						<div className="mt-4 p-3 bg-red-950/50 border border-red-900 rounded-lg text-red-400 text-xs">
							{error}
						</div>
					)}
					{success && (
						<div className="mt-4 p-3 bg-green-950/50 border border-green-900 rounded-lg text-green-400 text-xs break-all">
							{success.includes("http") ? (
								<>
									Account created!{" "}
									<a
										href={success.match(/http\S+/)?.[0]}
										className="underline text-amber-400 hover:text-amber-300"
									>
										Click to verify email
									</a>
									<span className="block mt-1 text-zinc-500">Or just sign in (verification not required in demo).</span>
								</>
							) : (
								success
							)}
						</div>
					)}
				</div>

				<p className="text-center text-zinc-600 text-xs mt-4">
					Powered by <span className="text-amber-600">theauth</span>
				</p>
			</div>
		</div>
	);
}
