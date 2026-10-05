import { useDeviceApproval } from "@glinr/theauth-react/query";
import type { FormEvent } from "react";
import { useId, useState } from "react";
import type { ClassNames, ErrorLabels, RunAction } from "./shared.js";
import { ErrorText, errorCodeOf, exec, visibleCode } from "./shared.js";

export interface DeviceApprovalLabels extends ErrorLabels {
	codeLabel: string;
	lookup: string;
	requestFrom: (clientName: string) => string;
	requesterIp: string;
	requesterUserAgent: string;
	abilities: string;
	approve: string;
	deny: string;
	approved: string;
	denied: string;
}

type Part = "form" | "input" | "lookup" | "request" | "approve" | "deny" | "result" | "error";

export interface DeviceApprovalProps {
	labels: DeviceApprovalLabels;
	/** Pre-fill from the verification URL (`verification_uri_complete`). */
	initialCode?: string;
	/** Host copy for an ability id; falls back to the raw id. */
	abilityLabel?: (ability: string) => string;
	classNames?: ClassNames<Part>;
	run?: RunAction;
}

export function DeviceApproval({
	labels,
	initialCode = "",
	abilityLabel = (a) => a,
	classNames = {},
	run,
}: DeviceApprovalProps) {
	const id = useId();
	const [input, setInput] = useState(initialCode);
	const [code, setCode] = useState(initialCode.trim());
	const { info, approve, deny } = useDeviceApproval(code);
	const done = approve.isSuccess ? "approved" : deny.isSuccess ? "denied" : null;
	const hasStepUp = !!run;

	const lookup = (e: FormEvent) => {
		e.preventDefault();
		approve.reset();
		deny.reset();
		setCode(input.trim());
	};

	const errorCode =
		visibleCode(approve.error, hasStepUp) ??
		visibleCode(deny.error, hasStepUp) ??
		(code ? errorCodeOf(info.error) : null);

	return (
		<div data-part="root">
			<form data-part="form" className={classNames.form} onSubmit={lookup}>
				<label htmlFor={`${id}-code`}>{labels.codeLabel}</label>
				<input
					id={`${id}-code`}
					data-part="input"
					className={classNames.input}
					value={input}
					onChange={(e) => setInput(e.target.value)}
					autoComplete="off"
					autoCapitalize="characters"
					spellCheck={false}
				/>
				<button
					type="submit"
					data-part="lookup"
					className={classNames.lookup}
					disabled={input.trim() === ""}
				>
					{labels.lookup}
				</button>
			</form>
			<ErrorText code={errorCode} labels={labels} className={classNames.error} />
			{info.data && !done && (
				<section data-part="request" className={classNames.request} aria-labelledby={`${id}-req`}>
					<h2 id={`${id}-req`}>{labels.requestFrom(info.data.clientName)}</h2>
					<dl>
						<dt>{labels.requesterIp}</dt>
						<dd data-part="requester-ip">{info.data.requesterIp}</dd>
						<dt>{labels.requesterUserAgent}</dt>
						<dd data-part="requester-user-agent">{info.data.requesterUserAgent}</dd>
						{info.data.abilities.length > 0 && (
							<>
								<dt>{labels.abilities}</dt>
								<dd>
									<ul data-part="abilities">
										{info.data.abilities.map((a) => (
											<li key={a}>{abilityLabel(a)}</li>
										))}
									</ul>
								</dd>
							</>
						)}
					</dl>
					<button
						type="button"
						data-part="approve"
						className={classNames.approve}
						disabled={approve.isPending || deny.isPending}
						onClick={() => void exec(run, () => approve.mutateAsync(undefined))}
					>
						{labels.approve}
					</button>
					<button
						type="button"
						data-part="deny"
						className={classNames.deny}
						disabled={approve.isPending || deny.isPending}
						onClick={() => void exec(run, () => deny.mutateAsync())}
					>
						{labels.deny}
					</button>
				</section>
			)}
			{done && (
				<p role="status" data-part="result" data-result={done} className={classNames.result}>
					{done === "approved" ? labels.approved : labels.denied}
				</p>
			)}
		</div>
	);
}
