import type { ApiTokenKind, MintedApiToken } from "@glinr/theauth-client";
import { authKeys, unwrap, useTheAuthGoClient } from "@glinr/theauth-react/query";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { FormEvent } from "react";
import { useId, useState } from "react";
import type { ClassNames, ErrorLabels, RunAction } from "./shared.js";
import { CopyButton, ErrorText, exec, visibleCode } from "./shared.js";

export interface AbilityOption {
	id: string;
	label: string;
}

export interface ExpiryOption {
	/** Lifetime in seconds. 0 means no expiry. */
	seconds: number;
	label: string;
}

export interface MintTokenFormLabels extends ErrorLabels {
	name: string;
	agentName: string;
	abilities: string;
	expiry: string;
	submit: string;
	secretTitle: string;
	secretNotice: string;
	copy: string;
	copied: string;
	dismiss: string;
}

type Part = "form" | "field" | "input" | "abilities" | "submit" | "secret" | "error" | "copy";

export interface MintTokenFormProps {
	labels: MintTokenFormLabels;
	/** Abilities the host lets the user pick from. */
	abilities: AbilityOption[];
	expiries?: ExpiryOption[];
	kind?: ApiTokenKind;
	classNames?: ClassNames<Part>;
	run?: RunAction;
	onMinted?: (token: MintedApiToken) => void;
}

export const ERROR_NAME_REQUIRED = "name_required";

export function MintTokenForm({
	labels,
	abilities,
	expiries = [],
	kind = "personal",
	classNames = {},
	run,
	onMinted,
}: MintTokenFormProps) {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const id = useId();
	const [name, setName] = useState("");
	const [agentName, setAgentName] = useState("");
	const [picked, setPicked] = useState<string[]>([]);
	const [expiry, setExpiry] = useState(expiries[0]?.seconds ?? 0);
	const [localError, setLocalError] = useState<string | null>(null);
	const [secret, setSecret] = useState<string | null>(null);

	const mint = useMutation<MintedApiToken, Error, void>({
		mutationFn: async () =>
			unwrap(
				await client.apiTokens.mint({
					name: name.trim(),
					abilities: picked,
					...(kind === "agent" ? { kind, agentName: agentName.trim() } : {}),
					...(expiry > 0 ? { expiresIn: expiry } : {}),
				}),
			),
		onSuccess: (token) => {
			setSecret(token.token);
			setName("");
			setAgentName("");
			setPicked([]);
			onMinted?.(token);
			return qc.invalidateQueries({ queryKey: authKeys.apiTokens() });
		},
	});

	if (secret !== null) {
		return (
			<section data-part="secret" className={classNames.secret} aria-labelledby={`${id}-secret`}>
				<h3 id={`${id}-secret`}>{labels.secretTitle}</h3>
				<p role="status">{labels.secretNotice}</p>
				<code data-part="secret-value">{secret}</code>
				<CopyButton
					value={secret}
					label={labels.copy}
					copiedLabel={labels.copied}
					className={classNames.copy}
				/>
				<button type="button" data-part="dismiss" onClick={() => setSecret(null)}>
					{labels.dismiss}
				</button>
			</section>
		);
	}

	const submit = (e: FormEvent) => {
		e.preventDefault();
		if (name.trim() === "") {
			setLocalError(ERROR_NAME_REQUIRED);
			return;
		}
		setLocalError(null);
		void exec(run, () => mint.mutateAsync());
	};

	const toggle = (ability: string) =>
		setPicked((cur) =>
			cur.includes(ability) ? cur.filter((a) => a !== ability) : [...cur, ability],
		);

	return (
		<form
			data-part="form"
			data-kind={kind}
			className={classNames.form}
			onSubmit={submit}
			noValidate
		>
			<div data-part="field" className={classNames.field}>
				<label htmlFor={`${id}-name`}>{labels.name}</label>
				<input
					id={`${id}-name`}
					data-part="input"
					className={classNames.input}
					value={name}
					onChange={(e) => setName(e.target.value)}
					aria-invalid={localError === ERROR_NAME_REQUIRED || undefined}
					required
				/>
			</div>
			{kind === "agent" && (
				<div data-part="field" className={classNames.field}>
					<label htmlFor={`${id}-agent`}>{labels.agentName}</label>
					<input
						id={`${id}-agent`}
						data-part="input"
						className={classNames.input}
						value={agentName}
						onChange={(e) => setAgentName(e.target.value)}
					/>
				</div>
			)}
			<fieldset data-part="abilities" className={classNames.abilities}>
				<legend>{labels.abilities}</legend>
				{abilities.map((a) => (
					<label key={a.id} data-part="ability">
						<input
							type="checkbox"
							checked={picked.includes(a.id)}
							onChange={() => toggle(a.id)}
							value={a.id}
						/>
						{a.label}
					</label>
				))}
			</fieldset>
			{expiries.length > 0 && (
				<div data-part="field" className={classNames.field}>
					<label htmlFor={`${id}-expiry`}>{labels.expiry}</label>
					<select
						id={`${id}-expiry`}
						data-part="input"
						className={classNames.input}
						value={expiry}
						onChange={(e) => setExpiry(Number(e.target.value))}
					>
						{expiries.map((o) => (
							<option key={o.seconds} value={o.seconds}>
								{o.label}
							</option>
						))}
					</select>
				</div>
			)}
			<ErrorText
				code={localError ?? visibleCode(mint.error, !!run)}
				labels={labels}
				className={classNames.error}
			/>
			<button
				type="submit"
				data-part="submit"
				className={classNames.submit}
				disabled={mint.isPending}
			>
				{labels.submit}
			</button>
		</form>
	);
}
