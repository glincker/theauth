import { Clock, ScrollText } from "lucide-react";
import type { AuditLogEntry, AuditResult } from "../api/types.js";
import { Badge } from "../components/badge.js";
import { Button } from "../components/button.js";
import { DecisionCodeBadge } from "../components/decision-code.js";
import { InputChips } from "../components/input-chips.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";

function resultVariant(result: AuditResult) {
	switch (result) {
		case "allowed":
			return "green" as const;
		case "denied":
			return "red" as const;
		case "rate_limited":
		case "escalated":
			return "yellow" as const;
	}
}

function formatTimestamp(iso: string) {
	const date = new Date(iso);
	return {
		date: date.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
		time: date.toLocaleTimeString("en-US", {
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
			hour12: false,
		}),
	};
}

function formatDuration(ms: number) {
	if (ms < 1) return "<1ms";
	if (ms < 1000) return `${ms}ms`;
	return `${(ms / 1000).toFixed(1)}s`;
}

function Head() {
	return (
		<TableHead>
			<Th>Timestamp</Th>
			<Th>Agent</Th>
			<Th>Action</Th>
			<Th>Resource</Th>
			<Th>Result</Th>
			<Th>Code</Th>
			<Th>Inputs</Th>
			<Th>Duration</Th>
			<Th>
				<span className="sr-only">Explain</span>
			</Th>
		</TableHead>
	);
}

interface AuditTableProps {
	entries: AuditLogEntry[];
	onExplain: (entry: AuditLogEntry) => void;
}

/** The audit rows, with the decision code column and a per-row explain action. */
export function AuditTable({ entries, onExplain }: AuditTableProps) {
	if (entries.length === 0) {
		return (
			<Table>
				<Head />
				<TableBody>
					<tr>
						<td colSpan={9}>
							<EmptyState
								icon={<ScrollText className="w-6 h-6" />}
								title="No audit events yet"
								description="Events are created automatically when agents call theauth.authorize(). Every allow and deny decision is recorded here."
								docsLink="https://theauth.dev/docs/audit"
							/>
						</td>
					</tr>
				</TableBody>
			</Table>
		);
	}
	return (
		<Table>
			<Head />
			<TableBody>
				{entries.map((entry) => {
					const ts = formatTimestamp(entry.timestamp);
					return (
						<Tr key={entry.id}>
							<Td>
								<div className="flex items-center gap-1.5">
									<Clock className="w-3 h-3 text-zinc-600 flex-shrink-0" />
									<div>
										<span className="text-xs text-zinc-700 dark:text-zinc-300 font-mono">
											{ts.time}
										</span>
										<span className="block text-[10px] text-zinc-600">{ts.date}</span>
									</div>
								</div>
							</Td>
							<Td>
								<span className="text-xs font-medium text-zinc-800 dark:text-zinc-200">
									{entry.agentName}
								</span>
							</Td>
							<Td>
								<code className="text-xs font-mono text-zinc-400">{entry.action}</code>
							</Td>
							<Td>
								<code className="text-xs font-mono text-zinc-400 max-w-[200px] truncate block">
									{entry.resource}
								</code>
							</Td>
							<Td>
								<Badge variant={resultVariant(entry.result)}>
									{entry.result.replace("_", " ")}
								</Badge>
							</Td>
							<Td>
								<DecisionCodeBadge code={entry.code} />
							</Td>
							<Td>
								<InputChips inputs={entry.inputs} />
							</Td>
							<Td>
								<span className="text-xs text-zinc-500 font-mono">
									{formatDuration(entry.durationMs)}
								</span>
							</Td>
							<Td>
								<Button
									variant="secondary"
									size="sm"
									onClick={() => onExplain(entry)}
									aria-label={`Explain decision for ${entry.action} on ${entry.resource}`}
								>
									Why
								</Button>
							</Td>
						</Tr>
					);
				})}
			</TableBody>
		</Table>
	);
}
