import type { StepUpMethod } from "@glinr/theauth-client";
import { useStepUp } from "@glinr/theauth-react/query";
import type { FormEvent, KeyboardEvent } from "react";
import { useEffect, useId, useRef, useState } from "react";
import type { ClassNames, ErrorLabels } from "./shared.js";
import { ErrorText, errorCodeOf } from "./shared.js";

export interface StepUpDialogLabels extends ErrorLabels {
	title: string;
	description?: string;
	methods: Record<StepUpMethod, string>;
	password: string;
	totpCode: string;
	passkeyPrompt: string;
	submit: string;
	cancel: string;
}

type Part =
	| "overlay"
	| "dialog"
	| "tablist"
	| "tab"
	| "panel"
	| "input"
	| "submit"
	| "cancel"
	| "error";

export interface StepUpDialogProps {
	open: boolean;
	onClose: () => void;
	/** Called with the end of the fresh-auth window once any method succeeds. */
	onElevated: (elevatedUntil: string) => void;
	labels: StepUpDialogLabels;
	methods?: StepUpMethod[];
	classNames?: ClassNames<Part>;
}

const ALL_METHODS: StepUpMethod[] = ["password", "totp", "passkey"];
const FOCUSABLE = 'button, input, [href], select, textarea, [tabindex]:not([tabindex="-1"])';

export function StepUpDialog({
	open,
	onClose,
	onElevated,
	labels,
	methods = ALL_METHODS,
	classNames = {},
}: StepUpDialogProps) {
	const { verify, passkey, isPasskeySupported } = useStepUp();
	const id = useId();
	const available = methods.filter((m) => m !== "passkey" || isPasskeySupported);
	const [active, setActive] = useState<StepUpMethod>(available[0] ?? "password");
	const [password, setPassword] = useState("");
	const [totp, setTotp] = useState("");
	const dialogRef = useRef<HTMLDivElement>(null);
	const tabRefs = useRef<Partial<Record<StepUpMethod, HTMLButtonElement | null>>>({});

	useEffect(() => {
		if (!open) return;
		const prev = document.activeElement as HTMLElement | null;
		dialogRef.current?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
		return () => {
			setPassword("");
			setTotp("");
			prev?.focus?.();
		};
	}, [open]);

	if (!open) return null;

	const done = (r: { elevatedUntil: string }) => onElevated(r.elevatedUntil);
	const submit = (e: FormEvent) => {
		e.preventDefault();
		if (active === "password") verify.mutate({ method: "password", password }, { onSuccess: done });
		else if (active === "totp") verify.mutate({ method: "totp", code: totp }, { onSuccess: done });
		else passkey.mutate(undefined, { onSuccess: done });
	};

	const onDialogKey = (e: KeyboardEvent) => {
		if (e.key === "Escape") {
			e.stopPropagation();
			onClose();
			return;
		}
		if (e.key !== "Tab") return;
		const nodes = Array.from(
			dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [],
		).filter((n) => !n.hasAttribute("disabled") && n.tabIndex >= 0);
		const first = nodes[0];
		const last = nodes[nodes.length - 1];
		if (!first || !last) return;
		if (e.shiftKey && document.activeElement === first) {
			e.preventDefault();
			last.focus();
		} else if (!e.shiftKey && document.activeElement === last) {
			e.preventDefault();
			first.focus();
		}
	};

	const onTabKey = (e: KeyboardEvent, index: number) => {
		const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
		let next = index;
		if (step !== 0) next = (index + step + available.length) % available.length;
		else if (e.key === "Home") next = 0;
		else if (e.key === "End") next = available.length - 1;
		else return;
		e.preventDefault();
		const m = available[next];
		if (!m) return;
		setActive(m);
		tabRefs.current[m]?.focus();
	};

	const pending = verify.isPending || passkey.isPending;
	const code = errorCodeOf(verify.error) ?? errorCodeOf(passkey.error);

	return (
		<div data-part="overlay" className={classNames.overlay}>
			<div
				ref={dialogRef}
				role="dialog"
				aria-modal="true"
				aria-labelledby={`${id}-title`}
				aria-describedby={labels.description ? `${id}-desc` : undefined}
				data-part="dialog"
				className={classNames.dialog}
				onKeyDown={onDialogKey}
			>
				<h2 id={`${id}-title`}>{labels.title}</h2>
				{labels.description && <p id={`${id}-desc`}>{labels.description}</p>}
				<div role="tablist" data-part="tablist" className={classNames.tablist}>
					{available.map((m, i) => (
						<button
							key={m}
							ref={(el) => {
								tabRefs.current[m] = el;
							}}
							type="button"
							role="tab"
							id={`${id}-tab-${m}`}
							aria-selected={active === m}
							aria-controls={`${id}-panel-${m}`}
							tabIndex={active === m ? 0 : -1}
							data-part="tab"
							data-active={active === m || undefined}
							className={classNames.tab}
							onClick={() => setActive(m)}
							onKeyDown={(e) => onTabKey(e, i)}
						>
							{labels.methods[m]}
						</button>
					))}
				</div>
				<form
					role="tabpanel"
					id={`${id}-panel-${active}`}
					aria-labelledby={`${id}-tab-${active}`}
					data-part="panel"
					className={classNames.panel}
					onSubmit={submit}
				>
					{active === "password" && (
						<>
							<label htmlFor={`${id}-pw`}>{labels.password}</label>
							<input
								id={`${id}-pw`}
								type="password"
								autoComplete="current-password"
								data-part="input"
								className={classNames.input}
								value={password}
								onChange={(e) => setPassword(e.target.value)}
							/>
						</>
					)}
					{active === "totp" && (
						<>
							<label htmlFor={`${id}-totp`}>{labels.totpCode}</label>
							<input
								id={`${id}-totp`}
								inputMode="numeric"
								autoComplete="one-time-code"
								data-part="input"
								className={classNames.input}
								value={totp}
								onChange={(e) => setTotp(e.target.value)}
							/>
						</>
					)}
					{active === "passkey" && <p>{labels.passkeyPrompt}</p>}
					<ErrorText code={code} labels={labels} className={classNames.error} />
					<button type="submit" data-part="submit" className={classNames.submit} disabled={pending}>
						{labels.submit}
					</button>
					<button type="button" data-part="cancel" className={classNames.cancel} onClick={onClose}>
						{labels.cancel}
					</button>
				</form>
			</div>
		</div>
	);
}
