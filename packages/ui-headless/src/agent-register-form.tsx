import type { RegisteredAgent } from "@glinr/theauth-client";
import { useAgents } from "@glinr/theauth-react/query";
import type { FormEvent } from "react";
import { useId, useState } from "react";
import type { ClassNames, ErrorLabels, RunAction } from "./shared.js";
import { CopyButton, ErrorText, exec, visibleCode } from "./shared.js";

export interface AgentRegisterFormLabels extends ErrorLabels {
	name: string;
	description: string;
	scope: string;
	submit: string;
	secretTitle: string;
	secretNotice: string;
	clientId: string;
	copy: string;
	copied: string;
	dismiss: string;
}

type Part = "form" | "field" | "input" | "submit" | "secret" | "error" | "copy";

export interface AgentRegisterFormProps {
	labels: AgentRegisterFormLabels;
	/** Scopes the host lets the user pick from; omit to hide the scope field. */
	scopes?: Array<{ id: string; label: string }>;
	classNames?: ClassNames<Part>;
	run?: RunAction;
	onRegistered?: (registered: RegisteredAgent) => void;
}

export const ERROR_AGENT_NAME_REQUIRED = "name_required";

export function AgentRegisterForm({
	labels,
	scopes = [],
	classNames = {},
	run,
	onRegistered,
}: AgentRegisterFormProps) {
	const { register } = useAgents();
	const id = useId();
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const [picked, setPicked] = useState<string[]>([]);
	const [localError, setLocalError] = useState<string | null>(null);
	const [created, setCreated] = useState<RegisteredAgent | null>(null);

	if (created !== null) {
		return (
			<section data-part="secret" className={classNames.secret} aria-labelledby={`${id}-secret`}>
				<h3 id={`${id}-secret`}>{labels.secretTitle}</h3>
				<p role="status">{labels.secretNotice}</p>
				<p data-part="client-id">
					<span>{labels.clientId}</span> <code>{created.credential.clientId}</code>
				</p>
				<code data-part="secret-value">{created.credential.secret}</code>
				<CopyButton
					value={created.credential.secret}
					label={labels.copy}
					copiedLabel={labels.copied}
					className={classNames.copy}
				/>
				<button type="button" data-part="dismiss" onClick={() => setCreated(null)}>
					{labels.dismiss}
				</button>
			</section>
		);
	}

	const submit = (e: FormEvent) => {
		e.preventDefault();
		if (name.trim() === "") {
			setLocalError(ERROR_AGENT_NAME_REQUIRED);
			return;
		}
		setLocalError(null);
		void exec(run, async () => {
			const registered = await register.mutateAsync({
				name: name.trim(),
				...(description.trim() ? { description: description.trim() } : {}),
				...(picked.length > 0 ? { scope: picked } : {}),
			});
			setCreated(registered);
			setName("");
			setDescription("");
			setPicked([]);
			onRegistered?.(registered);
		});
	};

	const toggle = (scope: string) =>
		setPicked((cur) => (cur.includes(scope) ? cur.filter((s) => s !== scope) : [...cur, scope]));

	return (
		<form data-part="form" className={classNames.form} onSubmit={submit} noValidate>
			<div data-part="field" className={classNames.field}>
				<label htmlFor={`${id}-name`}>{labels.name}</label>
				<input
					id={`${id}-name`}
					data-part="input"
					className={classNames.input}
					value={name}
					onChange={(e) => setName(e.target.value)}
					aria-invalid={localError === ERROR_AGENT_NAME_REQUIRED || undefined}
					required
				/>
			</div>
			<div data-part="field" className={classNames.field}>
				<label htmlFor={`${id}-description`}>{labels.description}</label>
				<input
					id={`${id}-description`}
					data-part="input"
					className={classNames.input}
					value={description}
					onChange={(e) => setDescription(e.target.value)}
				/>
			</div>
			{scopes.length > 0 && (
				<fieldset data-part="scopes">
					<legend>{labels.scope}</legend>
					{scopes.map((s) => (
						<label key={s.id} data-part="scope">
							<input
								type="checkbox"
								checked={picked.includes(s.id)}
								onChange={() => toggle(s.id)}
								value={s.id}
							/>
							{s.label}
						</label>
					))}
				</fieldset>
			)}
			<ErrorText
				code={localError ?? visibleCode(register.error, !!run)}
				labels={labels}
				className={classNames.error}
			/>
			<button
				type="submit"
				data-part="submit"
				className={classNames.submit}
				disabled={register.isPending}
			>
				{labels.submit}
			</button>
		</form>
	);
}
