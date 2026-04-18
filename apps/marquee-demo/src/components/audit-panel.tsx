"use client";

interface AuditEntry {
	id: string;
	action: string;
	resource: string;
	result: string;
	timestamp: string;
	durationMs: number;
}

interface AuditPanelProps {
	entries: AuditEntry[];
}

export function AuditPanel({ entries }: AuditPanelProps) {
	if (entries.length === 0) {
		return (
			<div className="text-zinc-500 text-sm italic py-4 text-center">
				Audit events will appear here as tool calls execute.
			</div>
		);
	}

	return (
		<div className="space-y-1 max-h-48 overflow-y-auto code-scroll">
			{entries.map((entry) => (
				<div
					key={entry.id}
					data-testid="audit-entry"
					className="flex items-center gap-3 px-3 py-2 rounded-md bg-zinc-900/60 text-xs font-mono"
				>
					<span
						className={
							entry.result === "allowed" ? "text-emerald-400 font-bold" : "text-red-400 font-bold"
						}
					>
						{entry.result === "allowed" ? "ALLOW" : "DENY"}
					</span>
					<span className="text-zinc-300">{entry.action}</span>
					<span className="text-brand truncate flex-1">{entry.resource}</span>
					<span className="text-zinc-600 shrink-0">{entry.durationMs}ms</span>
				</div>
			))}
		</div>
	);
}
