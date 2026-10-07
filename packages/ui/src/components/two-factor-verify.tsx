import type { ClipboardEvent, FormEvent, KeyboardEvent, ReactNode } from "react";
import { useCallback, useRef, useState } from "react";
import type { ButtonSlotProps, ErrorSlotProps, TwoFactorVerifyProps } from "../types.js";
import { cx } from "../utils.js";
import { AuthCard } from "./auth-card.js";

// ─── Default slots ───────────────────────────────────────────────────────────

function DefaultButton({ loading, children, ...rest }: ButtonSlotProps): ReactNode {
	return (
		<button
			{...rest}
			disabled={rest.disabled ?? loading}
			className={
				rest.className ??
				"theauth-btn w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
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

function DefaultError({ message, className }: ErrorSlotProps): ReactNode {
	return (
		<div
			className={
				className ??
				"theauth-error rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
			}
		>
			{message}
		</div>
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

export function TwoFactorVerify({
	classNames,
	components,
	basePath = "/api/theauth",
	onSuccess,
	onCancel,
	digits = 6,
	showBackupOption = true,
	title = "Two-factor authentication",
	className,
}: TwoFactorVerifyProps): ReactNode {
	const [code, setCode] = useState<string[]>(Array.from({ length: digits }, () => ""));
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [useBackup, setUseBackup] = useState(false);
	const [backupCode, setBackupCode] = useState("");
	const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

	const base = basePath.replace(/\/$/, "");
	const digitKeys = Array.from({ length: digits }, (_, i) => `digit-${i}`);

	const Btn = components?.Button ?? DefaultButton;
	const Err = components?.Error ?? DefaultError;

	const handleDigitChange = (index: number, value: string) => {
		if (value.length > 1) {
			const chars = value.replace(/\D/g, "").split("").slice(0, digits);
			const newCode = [...code];
			for (let i = 0; i < chars.length; i++) {
				if (index + i < digits) {
					newCode[index + i] = chars[i];
				}
			}
			setCode(newCode);
			const nextIdx = Math.min(index + chars.length, digits - 1);
			inputRefs.current[nextIdx]?.focus();
			return;
		}

		if (!/^\d?$/.test(value)) return;

		const newCode = [...code];
		newCode[index] = value;
		setCode(newCode);

		if (value && index < digits - 1) {
			inputRefs.current[index + 1]?.focus();
		}
	};

	const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
		if (e.key === "Backspace" && !code[index] && index > 0) {
			inputRefs.current[index - 1]?.focus();
		}
	};

	const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
		e.preventDefault();
		const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, digits);
		if (pasted.length > 0) {
			const newCode = Array.from({ length: digits }, () => "");
			for (let i = 0; i < pasted.length; i++) {
				newCode[i] = pasted[i];
			}
			setCode(newCode);
			const nextIdx = Math.min(pasted.length, digits - 1);
			inputRefs.current[nextIdx]?.focus();
		}
	};

	const handleSubmit = useCallback(
		async (e: FormEvent) => {
			e.preventDefault();
			setIsLoading(true);
			setError(null);

			const payload = useBackup ? { backupCode } : { code: code.join("") };

			if (!useBackup && code.join("").length !== digits) {
				setError(`Enter all ${digits} digits`);
				setIsLoading(false);
				return;
			}

			try {
				const res = await fetch(`${base}/auth/two-factor/verify`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(payload),
				});

				if (res.ok) {
					onSuccess?.();
				} else {
					const json = (await res.json()) as { error?: { message?: string } };
					setError(json.error?.message ?? "Invalid code");
				}
			} catch {
				setError("Network error");
			} finally {
				setIsLoading(false);
			}
		},
		[code, backupCode, useBackup, digits, base, onSuccess],
	);

	return (
		<AuthCard
			classNames={{
				root: classNames?.root ?? className,
				card: classNames?.card,
				title: classNames?.title,
			}}
			title={title}
		>
			<div className="flex flex-col gap-4">
				<p
					className={cx(
						"theauth-2fa-desc text-center text-sm text-zinc-500 dark:text-zinc-400",
						classNames?.description,
					)}
				>
					{useBackup
						? "Enter one of your backup codes"
						: "Enter the code from your authenticator app"}
				</p>

				{error && <Err message={error} />}

				<form onSubmit={handleSubmit} className={cx("flex flex-col gap-4", classNames?.form)}>
					{useBackup ? (
						<input
							type="text"
							value={backupCode}
							onChange={(e) => setBackupCode(e.target.value)}
							placeholder="Backup code"
							autoComplete="one-time-code"
							disabled={isLoading}
							className={cx(
								"theauth-input w-full rounded-lg border border-zinc-300 bg-white px-3 py-2.5 text-center font-mono text-sm tracking-widest text-zinc-900 outline-none transition-colors placeholder:text-zinc-400 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400",
								classNames?.input,
							)}
						/>
					) : (
						<div className="flex justify-center gap-2">
							{Array.from({ length: digits }).map((_, i) => (
								<input
									key={digitKeys[i]}
									ref={(el) => {
										inputRefs.current[i] = el;
									}}
									type="text"
									inputMode="numeric"
									autoComplete={i === 0 ? "one-time-code" : "off"}
									maxLength={1}
									value={code[i]}
									onChange={(e) => handleDigitChange(i, e.target.value)}
									onKeyDown={(e) => handleKeyDown(i, e)}
									onPaste={i === 0 ? handlePaste : undefined}
									disabled={isLoading}
									className={cx(
										"theauth-2fa-digit h-12 w-10 rounded-lg border border-zinc-300 bg-white text-center font-mono text-lg text-zinc-900 outline-none transition-colors focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400",
										classNames?.input,
									)}
								/>
							))}
						</div>
					)}

					<Btn type="submit" loading={isLoading}>
						Verify
					</Btn>
				</form>

				<div className="flex items-center justify-between">
					{showBackupOption && (
						<button
							type="button"
							onClick={() => {
								setUseBackup((v) => !v);
								setError(null);
							}}
							className={cx(
								"theauth-backup-link text-xs text-zinc-500 transition-colors hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200",
								classNames?.backupLink,
							)}
						>
							{useBackup ? "Use authenticator code" : "Use backup code"}
						</button>
					)}
					{onCancel && (
						<button
							type="button"
							onClick={onCancel}
							className="text-xs text-zinc-500 transition-colors hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
						>
							Cancel
						</button>
					)}
				</div>
			</div>
		</AuthCard>
	);
}
