import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type { ExplainRequest } from "../api/types.js";
import { Button } from "../components/button.js";
import { ExplainView } from "../components/explain-drawer.js";
import { FormGroup, Input, Label } from "../components/input.js";
import { PageHeader } from "../components/layout.js";

export interface ExplainForm {
	agentId: string;
	action: string;
	resource: string;
}

/** Trimmed request, or the first missing field's message. */
export function buildExplainRequest(form: ExplainForm): ExplainRequest | string {
	const agentId = form.agentId.trim();
	const action = form.action.trim();
	const resource = form.resource.trim();
	if (!agentId) return "Agent id is required";
	if (!action) return "Action is required";
	if (!resource) return "Resource is required";
	return { agentId, action, resource };
}

/** Asks POST /explain about any agent, action and resource. Nothing is recorded, and near misses come with the answer. */
export function ExplainPage({ client }: { client: TheAuthApiClient }) {
	const [form, setForm] = useState<ExplainForm>({ agentId: "", action: "", resource: "" });
	const [formError, setFormError] = useState<string | null>(null);
	const explain = useMutation({
		mutationFn: (request: ExplainRequest) => client.explainDecision(request),
	});

	function submit(event: React.FormEvent) {
		event.preventDefault();
		const request = buildExplainRequest(form);
		if (typeof request === "string") {
			setFormError(request);
			return;
		}
		setFormError(null);
		explain.mutate(request);
	}

	const set = (key: keyof ExplainForm) => (event: React.ChangeEvent<HTMLInputElement>) =>
		setForm((cur) => ({ ...cur, [key]: event.target.value }));

	return (
		<div>
			<PageHeader
				title="Explain"
				description="Ask why an agent would be allowed or denied an action on a resource, with the closest grants that nearly matched."
			/>
			<form onSubmit={submit} className="max-w-xl space-y-4 mb-8" aria-label="Explain a decision">
				<FormGroup>
					<Label htmlFor="explain-agent" required>
						Agent id
					</Label>
					<Input id="explain-agent" value={form.agentId} onChange={set("agentId")} />
				</FormGroup>
				<FormGroup>
					<Label htmlFor="explain-action" required>
						Action
					</Label>
					<Input
						id="explain-action"
						value={form.action}
						onChange={set("action")}
						placeholder="read"
					/>
				</FormGroup>
				<FormGroup>
					<Label htmlFor="explain-resource" required>
						Resource
					</Label>
					<Input
						id="explain-resource"
						value={form.resource}
						onChange={set("resource")}
						placeholder="mcp:github:issues"
					/>
				</FormGroup>
				{formError && (
					<p role="alert" className="text-xs text-red-400">
						{formError}
					</p>
				)}
				<Button type="submit" variant="primary" loading={explain.isPending}>
					Explain
				</Button>
			</form>

			{explain.data && !explain.data.success && (
				<p role="alert" className="text-sm text-red-500">
					{explain.data.error.message}
				</p>
			)}
			{explain.data?.success && (
				<div className="max-w-xl">
					<ExplainView result={explain.data.data} />
				</div>
			)}
		</div>
	);
}
