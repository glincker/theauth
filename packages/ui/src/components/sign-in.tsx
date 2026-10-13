import { useSignIn } from "@glinr/theauth-react";
import type { FormEvent, ReactNode } from "react";
import { useCallback, useEffect, useState } from "react";
import type { LinkSlotProps, SignInProps } from "../types.js";
import { cx } from "../utils.js";
import { AuthCard } from "./auth-card.js";
import { DefaultButton, DefaultDivider, DefaultError, DefaultInput } from "./defaults.js";
import { OAuthButtons } from "./oauth-buttons.js";

// Default slots

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
				"theauth-link text-sm text-zinc-500 transition-colors hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
			}
		>
			{children}
		</a>
	);
}

// Component

export function SignIn({
	classNames,
	passkeyClient,
	passkeyAutofill = true,
	components,
	providers = [],
	basePath = "/api/theauth",
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
	const [passkeyError, setPasskeyError] = useState<string | null>(null);
	const [autofillActive, setAutofillActive] = useState(false);
	// Decided after mount so server and client markup agree.
	const [passkeyReady, setPasskeyReady] = useState(false);

	const finishPasskey = useCallback(
		(result: Awaited<ReturnType<NonNullable<typeof passkeyClient>["signIn"]>>) => {
			if (result.ok) onSuccess?.();
			else if (result.reason !== "cancelled") setPasskeyError(result.message);
		},
		[onSuccess],
	);

	// Conditional UI: the browser lists saved passkeys in the email field.
	useEffect(() => {
		setPasskeyReady(passkeyClient?.isSupported() === true);
	}, [passkeyClient]);

	useEffect(() => {
		if (!passkeyClient || !passkeyAutofill || !passkeyClient.isSupported()) return;
		const controller = new AbortController();
		let alive = true;
		void passkeyClient.isConditionalAvailable().then((available) => {
			if (!alive || !available) return;
			setAutofillActive(true);
			void passkeyClient.signIn({ conditional: true, signal: controller.signal }).then((r) => {
				if (alive) finishPasskey(r);
			});
		});
		return () => {
			alive = false;
			controller.abort();
		};
	}, [passkeyClient, passkeyAutofill, finishPasskey]);

	const handlePasskeyClick = useCallback(async () => {
		if (!passkeyClient) return;
		setPasskeyError(null);
		finishPasskey(await passkeyClient.signIn());
	}, [passkeyClient, finishPasskey]);
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
						<div className={cx("theauth-oauth-section", classNames?.oauthSection)}>
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
							autoComplete={autofillActive ? "username webauthn" : "email"}
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

				{/* Passkey */}
				{passkeyClient && passkeyReady && (
					<>
						{passkeyError && <Err message={passkeyError} className={cx("", classNames?.error)} />}
						<Divider label="or" />
						<Btn type="button" onClick={handlePasskeyClick} disabled={disabled}>
							Sign in with a passkey
						</Btn>
					</>
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
							"theauth-footer text-center text-sm text-zinc-500 dark:text-zinc-400",
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
