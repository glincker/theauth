import type { AuditInputRef, InputSourceKind } from "../api/types.js";
import { Badge } from "./badge.js";

const KIND_LABEL: Record<InputSourceKind, string> = {
	user_message: "user",
	tool_output: "tool",
	retrieved_document: "doc",
	agent: "agent",
};

/** Untrusted sources get a warning color, the user's own message stays neutral. */
const KIND_VARIANT: Record<InputSourceKind, "gray" | "yellow" | "blue" | "indigo"> = {
	user_message: "gray",
	tool_output: "blue",
	retrieved_document: "yellow",
	agent: "indigo",
};

const MAX_CHIPS = 4;

/** What was in context for a call: one chip per recorded input, with the source id or a short hash prefix. */
export function InputChips({ inputs }: { inputs?: AuditInputRef[] }) {
	if (!inputs || inputs.length === 0) return <span className="text-xs text-zinc-600">-</span>;
	const shown = inputs.slice(0, MAX_CHIPS);
	return (
		<div className="flex flex-wrap gap-1" data-testid="input-chips">
			{shown.map((input) => (
				<span key={`${input.kind}:${input.hash}`} title={`${input.kind} ${input.hash}`}>
					<Badge variant={KIND_VARIANT[input.kind]}>
						{KIND_LABEL[input.kind]}
						<code className="font-mono text-[10px]">{input.id ?? input.hash.slice(0, 8)}</code>
					</Badge>
				</span>
			))}
			{inputs.length > MAX_CHIPS && (
				<span className="text-[10px] text-zinc-500">+{inputs.length - MAX_CHIPS}</span>
			)}
		</div>
	);
}
