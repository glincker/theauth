import { useSignIn } from "@theauth/react";
import type { FormEvent, ReactNode } from "react";
import { useCallback, useState } from "react";
import type {
	ButtonSlotProps,
	DividerSlotProps,
	ErrorSlotProps,
	InputSlotProps,
	LinkSlotProps,
	SignInProps,
} from "../types.js";
import { cx } from "../utils.js";
import { AuthCard } from "./auth-card.js";
import { OAuthButtons } from "./oauth-buttons.js";

// ─── Default slots ───────────────────────────────────────────────────────────

function DefaultInput({ label, error, ...rest }: InputSlotProps): ReactNode {
	return (
		<label className="kavach-field flex flex-col gap-1.5">
			<span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</span>
			<input
				{...rest}
				className={
					rest.className ??
					"kavach-input w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition-colors placeholder:text-zinc-400 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
				}
			/>
			{error && <p className="text-xs text-red-500">{error}</p>}
		</label>
	);
}

function DefaultButton({ loading, children, ...rest }: ButtonSlotProps): ReactNode {
	return (
		<button
			{...rest}
			disabled={rest.disabled ?? loading}
			className={
				rest.className ??
				"kavach-btn w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
			}
		>
			{loading ? (
				<span className="flex items-center justify-center gap-2">
					<Spinner />
					{children}
				</span>
			) : (
				children
			)}
		</button>
	);
}

function DefaultDivider({ label, className }: DividerSlotProps): ReactNode {
	return (
		<div className={className ?? "kavach-divider flex items-center gap-3 py-1"}>
			<div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
			{label && <span className="text-xs text-zinc-400">{label}</span>}
			<div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
		</div>
	);
}

function DefaultError({ message, className }: ErrorSlotProps): ReactNode {
	return (
		<div
			className={
				className ??
				"kavach-error rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
			}
		>
			{message}
		</div>
	);
}

function DefaultLink({ href, children, className, onClick }: LinkSlotProps): ReactNode {
	return (
		<a
			href={href}
			onClick={
				onClick
					? (e: React.MouseEvent) => {
							e.preventDefault();
							onClick();
						}
					: undefined
			}
			className={
				className ??
				"kavach-link text-sm text-zinc-500 transition-colors hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
			}
		>
			{children}
		</a>
	);
}

function Spinner(): ReactNode {
	return (
		<svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
			<circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
			<path
				className="opacity-75"
				fill="currentColor"
				d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
			/>
		</svg>
	);
}

// ─── Component ───────────────────────────────────────────────────────────────

export function SignIn({
	classNames,
	components,
	providers = [],
	basePath = "/api/kavach",
	onSuccess,
	forgotPasswordUrl,
	onForgotPassword,
	signUpUrl,
	onSignUp,
	showMagicLink = false,
	title = "Sign in",
	footer,
	disabled,
	className,
}: SignInProps): ReactNode {
	const { signIn, isLoading, error } = useSignIn();
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [mode, setMode] = useState<"password" | "magic-link">("password");
	const [magicLinkSent, setMagicLinkSent] = useState(false);
	const [magicLinkLoading, setMagicLinkLoading] = useState(false);
	const [magicLinkError, setMagicLinkError] = useState<string | null>(null);

	const Input = components?.Input ?? DefaultInput;
	const Btn = components?.Button ?? DefaultButton;
	const Divider = components?.Divider ?? DefaultDivider;
	const Err = components?.Error ?? DefaultError;
	const Link = components?.Link ?? DefaultLink;

	const base = basePath.replace(/\/$/, "");

	const handlePasswordSubmit = useCallback(
		async (e: FormEvent) => {
			e.preventDefault();
			if (!email || !password) return;
			const result = await signIn(email, password);
			if (result.success) {
				onSuccess?.();
			}
		},
		[email, password, signIn, onSuccess],
	);

	const handleMagicLinkSubmit = useCallback(
		async (e: FormEvent) => {
			e.preventDefault();
			if (!email) return;
			setMagicLinkLoading(true);
			setMagicLinkError(null);
			try {
				const res = await fetch(`${base}/auth/magic-link/send`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email }),
				});
				if (res.ok) {
					setMagicLinkSent(true);
				} else {
					const json = (await res.json()) as { error?: { message?: string } };
					setMagicLinkError(json.error?.message ?? "Failed to send magic link");
				}
			} catch {
				setMagicLinkError("Network error");
			} finally {
				setMagicLinkLoading(false);
			}
		},
		[email, base],
	);

	return (
		<AuthCard
			classNames={{
				root: classNames?.root ?? className,
				card: classNames?.card,
				title: classNames?.title,
			}}
			title={title}
			description="Enter your credentials to continue"
		>
			<div className="flex flex-col gap-4">
				{/* OAuth providers */}
				{providers.length > 0 && (
					<>
						<div className={cx("kavach-oauth-section", classNames?.oauthSection)}>
							<OAuthButtons
								providers={providers}
								basePath={basePath}
								mode="signin"
								layout={providers.length > 3 ? "grid" : "list"}
								disabled={disabled}
								components={components ? { Button: components.Button } : undefined}
							/>
						</div>
						<Divider label="or" />
					</>
				)}

				{/* Mode toggle for magic link */}
				{showMagicLink && (
					<div className="flex gap-1 rounded-lg bg-zinc-100 p-1 dark:bg-zinc-800">
						<button
							type="button"
							onClick={() => setMode("password")}
							className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
								mode === "password"
									? "bg-white text-zinc-900 shadow-sm dark:bg-zinc-700 dark:text-zinc-100"
									: "text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
							}`}
						>
							Password
						</button>
						<button
							type="button"
							onClick={() => setMode("magic-link")}
							className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
								mode === "magic-link"
									? "bg-white text-zinc-900 shadow-sm dark:bg-zinc-700 dark:text-zinc-100"
									: "text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
							}`}
						>
							Magic link
						</button>
					</div>
				)}

				{/* Password mode */}
				{mode === "password" && (
					<form
						onSubmit={handlePasswordSubmit}
						className={cx("flex flex-col gap-4", classNames?.form)}
					>
						{error && <Err message={error} className={cx("", classNames?.error)} />}

						<Input
							label="Email"
							type="email"
							name="email"
							placeholder="you@example.com"
							value={email}
							onChange={(e) => setEmail(e.target.value)}
							required
							autoComplete="email"
							disabled={disabled ?? isLoading}
						/>

						<Input
							label="Password"
							type="password"
							name="password"
							placeholder="Enter your password"
							value={password}
							onChange={(e) => setPassword(e.target.value)}
							required
							autoComplete="current-password"
							disabled={disabled ?? isLoading}
						/>

						{(forgotPasswordUrl ?? onForgotPassword) && (
							<div className="flex justify-end -mt-2">
								<Link href={forgotPasswordUrl ?? "#"} onClick={onForgotPassword}>
									Forgot password?
								</Link>
							</div>
						)}

						<Btn type="submit" loading={isLoading} disabled={disabled}>
							Sign in
						</Btn>
					</form>
				)}

				{/* Magic link mode */}
				{mode === "magic-link" && !magicLinkSent && (
					<form
						onSubmit={handleMagicLinkSubmit}
						className={cx("flex flex-col gap-4", classNames?.form)}
					>
						{magicLinkError && <Err message={magicLinkError} />}

						<Input
							label="Email"
							type="email"
							name="email"
							placeholder="you@example.com"
							value={email}
							onChange={(e) => setEmail(e.target.value)}
							required
							autoComplete="email"
							disabled={disabled ?? magicLinkLoading}
						/>

						<Btn type="submit" loading={magicLinkLoading} disabled={disabled}>
							Send magic link
						</Btn>
					</form>
				)}

				{mode === "magic-link" && magicLinkSent && (
					<div className="rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-center text-sm text-green-700 dark:border-green-800 dark:bg-green-900/20 dark:text-green-400">
						<p className="font-medium">Check your email</p>
						<p className="mt-1 text-xs opacity-80">We sent a sign-in link to {email}</p>
						<button
							type="button"
							onClick={() => setMagicLinkSent(false)}
							className="mt-2 text-xs underline opacity-60 hover:opacity-100"
						>
							Try again
						</button>
					</div>
				)}

				{/* Footer: sign up link */}
				{(signUpUrl ?? onSignUp) && (
					<p
						className={cx(
							"kavach-footer text-center text-sm text-zinc-500 dark:text-zinc-400",
							classNames?.footer,
						)}
					>
						Don&apos;t have an account?{" "}
						<Link
							href={signUpUrl ?? "#"}
							onClick={onSignUp}
							className="font-medium text-zinc-900 hover:underline dark:text-zinc-100"
						>
							Sign up
						</Link>
					</p>
				)}

				{footer}
			</div>
		</AuthCard>
	);
}
