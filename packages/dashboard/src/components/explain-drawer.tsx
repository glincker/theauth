import { useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { useEffect } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type { AuditLogEntry, ExplainResponse } from "../api/types.js";
import { Badge } from "./badge.js";
import { DecisionCodeBadge } from "./decision-code.js";

function stepVariant(outcome: string) {
	if (outcome === "pass") return "green" as const;
	if (outcome === "approval") return "yellow" as const;
	return "red" as const;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
	return (
		<section className="mb-5">
			<h3 className="text-[11px] uppercase tracking-wide text-zinc-500 mb-2">{title}</h3>
			{children}
		</section>
	);
}

/** The explain result as readable sections. Pure, so it renders without a network. */
export function ExplainView({ result }: { result: ExplainResponse }) {
	return (
		<div data-testid="explain-view">
			<Section title="Decision">
				<div className="flex items-center gap-2 mb-2">
					<Badge
						variant={result.allowed ? "green" : result.decision === "escalate" ? "yellow" : "red"}
					>
						{result.decision}
					</Badge>
					<DecisionCodeBadge code={result.code} />
				</div>
				<p className="text-sm text-zinc-700 dark:text-zinc-300">{result.reason}</p>
			</Section>

			{result.matchedGrant && (
				<Section title="Matched grant">
					<code className="text-xs font-mono text-zinc-600 dark:text-zinc-400 break-all">
						{result.matchedGrant.permission.resource} [
						{result.matchedGrant.permission.actions.join(", ")}]
					</code>
					<span className="block text-xs text-zinc-500 mt-1">
						{result.matchedGrant.source}, resource {result.matchedGrant.resourceMatch}, action{" "}
						{result.matchedGrant.actionMatch}
					</span>
				</Section>
			)}

			{result.constraints.length > 0 && (
				<Section title="Constraints">
					<ul className="space-y-1.5">
						{result.constraints.map((step) => (
							<li key={step.constraint} className="flex items-start gap-2 text-xs">
								<Badge variant={stepVariant(step.outcome)}>{step.outcome}</Badge>
								<span className="text-zinc-700 dark:text-zinc-300">
									<code className="font-mono">{step.constraint}</code>: {step.detail}
								</span>
							</li>
						))}
					</ul>
				</Section>
			)}

			{result.hook.configured && (
				<Section title="Hook">
					<p className="text-xs text-zinc-700 dark:text-zinc-300">
						{result.hook.evaluated
							? `${result.hook.outcome ?? "ran"}${result.hook.guard ? ` (${result.hook.guard})` : ""}${
									result.hook.elapsedMs === undefined ? "" : ` in ${result.hook.elapsedMs}ms`
								}${result.hook.reason ? `: ${result.hook.reason}` : ""}`
							: "Configured, not run for this explanation."}
					</p>
				</Section>
			)}

			{result.nearMisses.length > 0 && (
				<Section title="Closest grants">
					<ul className="space-y-1.5">
						{result.nearMisses.map((miss) => (
							<li
								key={`${miss.source}:${miss.grant.resource}`}
								className="text-xs text-zinc-700 dark:text-zinc-300"
							>
								{miss.hint}
							</li>
						))}
					</ul>
				</Section>
			)}
		</div>
	);
}

interface ExplainDrawerProps {
	client: TheAuthApiClient;
	entry: AuditLogEntry | null;
	onClose: () => void;
}

/** Side drawer that asks POST /explain why the selected audit row was decided the way it was. */
export function ExplainDrawer({ client, entry, onClose }: ExplainDrawerProps) {
	const { data, isLoading } = useQuery({
		queryKey: ["explain", entry?.id],
		queryFn: () =>
			client.explainDecision({
				agentId: entry?.agentId ?? "",
				action: entry?.action ?? "",
				resource: entry?.resource ?? "",
				at: entry?.timestamp,
			}),
		enabled: entry !== null,
		retry: false,
	});

	useEffect(() => {
		if (!entry) return;
		const onKey = (event: KeyboardEvent) => {
			if (event.key === "Escape") onClose();
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [entry, onClose]);

	if (!entry) return null;

	return (
		<div className="fixed inset-0 z-50 flex justify-end">
			<div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
			<aside
				role="dialog"
				aria-modal="true"
				aria-label="Decision explanation"
				className="relative w-full max-w-md h-full overflow-auto bg-white dark:bg-zinc-900 border-l border-zinc-200 dark:border-zinc-800 p-6"
			>
				<div className="flex items-start justify-between mb-5">
					<div>
						<h2 className="text-base font-semibold text-zinc-900 dark:text-white">
							Why this decision
						</h2>
						<code className="block text-xs font-mono text-zinc-500 mt-1 break-all">
							{entry.action} on {entry.resource}
						</code>
					</div>
					<button
						type="button"
						onClick={onClose}
						className="w-7 h-7 flex items-center justify-center rounded-lg text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800"
						aria-label="Close explanation"
					>
						<X className="w-4 h-4" />
					</button>
				</div>
				<p className="text-xs text-zinc-500 mb-4">
					Re-evaluated now against the current rules, as of the row's time. The recorded decision
					was <DecisionCodeBadge code={entry.code} />
				</p>
				{isLoading && <p className="text-sm text-zinc-500">Loading</p>}
				{data && !data.success && (
					<p role="alert" className="text-sm text-red-500">
						{data.error.message}
					</p>
				)}
				{data?.success && <ExplainView result={data.data} />}
			</aside>
		</div>
	);
}
