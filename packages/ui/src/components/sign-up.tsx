import { useSignUp } from "@glinr/theauth-react";
import type { FormEvent, ReactNode } from "react";
import { useCallback, useState } from "react";
import type { LinkSlotProps, SignUpProps } from "../types.js";
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
				"theauth-link text-sm font-medium text-zinc-900 hover:underline dark:text-zinc-100"
			}
		>
			{children}
		</a>
	);
}

// Component

export function SignUp({
	classNames,
	components,
	providers = [],
	basePath = "/api/theauth",
	onSuccess,
	signInUrl,
	onSignIn,
	showName = true,
	confirmPassword = true,
	title = "Create account",
	footer,
	disabled,
	className,
}: SignUpProps): ReactNode {
	const { signUp, isLoading, error } = useSignUp();
	const [name, setName] = useState("");
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [passwordConfirm, setPasswordConfirm] = useState("");
	const [localError, setLocalError] = useState<string | null>(null);

	const Input = components?.Input ?? DefaultInput;
	const Btn = components?.Button ?? DefaultButton;
	const Divider = components?.Divider ?? DefaultDivider;
	const Err = components?.Error ?? DefaultError;
	const Link = components?.Link ?? DefaultLink;

	const handleSubmit = useCallback(
		async (e: FormEvent) => {
			e.preventDefault();
			setLocalError(null);

			if (confirmPassword && password !== passwordConfirm) {
				setLocalError("Passwords don't match");
				return;
			}

			if (password.length < 8) {
				setLocalError("Password must be at least 8 characters");
				return;
			}

			const result = await signUp(email, password, showName ? name || undefined : undefined);
			if (result.success) {
				onSuccess?.();
			}
		},
		[email, password, passwordConfirm, name, signUp, onSuccess, confirmPassword, showName],
	);

	const displayError = localError ?? error;

	return (
		<AuthCard
			classNames={{
				root: classNames?.root ?? className,
				card: classNames?.card,
				title: classNames?.title,
			}}
			title={title}
			description="Enter your details to get started"
		>
			<div className="flex flex-col gap-4">
				{/* OAuth providers */}
				{providers.length > 0 && (
					<>
						<div className={cx("theauth-oauth-section", classNames?.oauthSection)}>
							<OAuthButtons
								providers={providers}
								basePath={basePath}
								mode="signup"
								layout={providers.length > 3 ? "grid" : "list"}
								disabled={disabled}
								components={components ? { Button: components.Button } : undefined}
							/>
						</div>
						<Divider label="or" />
					</>
				)}

				<form onSubmit={handleSubmit} className={cx("flex flex-col gap-4", classNames?.form)}>
					{displayError && <Err message={displayError} />}

					{showName && (
						<Input
							label="Name"
							type="text"
							name="name"
							placeholder="Your name"
							value={name}
							onChange={(e) => setName(e.target.value)}
							autoComplete="name"
							disabled={disabled ?? isLoading}
						/>
					)}

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
						placeholder="At least 8 characters"
						value={password}
						onChange={(e) => setPassword(e.target.value)}
						required
						minLength={8}
						autoComplete="new-password"
						disabled={disabled ?? isLoading}
					/>

					{confirmPassword && (
						<Input
							label="Confirm password"
							type="password"
							name="password-confirm"
							placeholder="Repeat your password"
							value={passwordConfirm}
							onChange={(e) => setPasswordConfirm(e.target.value)}
							required
							autoComplete="new-password"
							disabled={disabled ?? isLoading}
						/>
					)}

					<Btn type="submit" loading={isLoading} disabled={disabled}>
						Create account
					</Btn>
				</form>

				{/* Footer: sign in link */}
				{(signInUrl ?? onSignIn) && (
					<p
						className={cx(
							"theauth-footer text-center text-sm text-zinc-500 dark:text-zinc-400",
							classNames?.footer,
						)}
					>
						Already have an account?{" "}
						<Link href={signInUrl ?? "#"} onClick={onSignIn}>
							Sign in
						</Link>
					</p>
				)}

				{footer}
			</div>
		</AuthCard>
	);
}
