import { useQuery } from "@tanstack/react-query";
import { Clock, Download, Filter, RefreshCw, ScrollText } from "lucide-react";
import { useRef, useState } from "react";
import type { KavachApiClient } from "../api/client.js";
import type { AuditLogFilters, AuditResult } from "../api/types.js";
import { Badge } from "../components/badge.js";
import { Button } from "../components/button.js";
import { Select } from "../components/input.js";
import { PageHeader } from "../components/layout.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function resultVariant(result: AuditResult) {
	switch (result) {
		case "allowed":
			return "green" as const;
		case "denied":
			return "red" as const;
		case "rate_limited":
			return "yellow" as const;
	}
}

function formatTimestamp(iso: string) {
	const date = new Date(iso);
	return {
		date: date.toLocaleDateString("en-US", {
			month: "short",
			day: "numeric",
		}),
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

// ─── Filter Bar ───────────────────────────────────────────────────────────────

interface FilterBarProps {
	filters: AuditLogFilters;
	agentOptions: Array<{ id: string; name: string }>;
	onChange: (filters: AuditLogFilters) => void;
}

const ACTION_OPTIONS = [
	"",
	"read",
	"write",
	"delete",
	"execute",
	"list",
	"authenticate",
	"authorize",
];
const RESULT_OPTIONS: Array<{ value: string; label: string }> = [
	{ value: "", label: "All results" },
	{ value: "allowed", label: "Allowed" },
	{ value: "denied", label: "Denied" },
	{ value: "rate_limited", label: "Rate limited" },
];

function FilterBar({ filters, agentOptions, onChange }: FilterBarProps) {
	return (
		<div className="flex flex-wrap items-center gap-2 mb-5 p-3 bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl">
			<Filter className="w-3.5 h-3.5 text-zinc-500 flex-shrink-0 ml-0.5" />

			<Select
				value={filters.agentId ?? ""}
				onChange={(e) => onChange({ ...filters, agentId: e.target.value || undefined, offset: 0 })}
				className="flex-1 min-w-[140px] max-w-[200px] py-1.5 text-xs"
			>
				<option value="">All agents</option>
				{agentOptions.map((a) => (
					<option key={a.id} value={a.id}>
						{a.name}
					</option>
				))}
			</Select>

			<Select
				value={filters.action ?? ""}
				onChange={(e) => onChange({ ...filters, action: e.target.value || undefined, offset: 0 })}
				className="flex-1 min-w-[120px] max-w-[160px] py-1.5 text-xs"
			>
				<option value="">All actions</option>
				{ACTION_OPTIONS.filter(Boolean).map((a) => (
					<option key={a} value={a}>
						{a}
					</option>
				))}
			</Select>

			<Select
				value={filters.result ?? ""}
				onChange={(e) =>
					onChange({
						...filters,
						result: (e.target.value as AuditResult) || undefined,
						offset: 0,
					})
				}
				className="flex-1 min-w-[130px] max-w-[180px] py-1.5 text-xs"
			>
				{RESULT_OPTIONS.map((o) => (
					<option key={o.value} value={o.value}>
						{o.label}
					</option>
				))}
			</Select>

			<input
				type="date"
				value={filters.from ? filters.from.slice(0, 10) : ""}
				onChange={(e) =>
					onChange({
						...filters,
						from: e.target.value ? `${e.target.value}T00:00:00Z` : undefined,
						offset: 0,
					})
				}
				className="bg-zinc-50 dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded-lg px-2.5 py-1.5 text-xs text-zinc-700 dark:text-zinc-300 focus:outline-none focus:ring-2 focus:ring-amber-500/30"
				aria-label="From date"
			/>
			<span className="text-zinc-600 text-xs">to</span>
			<input
				type="date"
				value={filters.to ? filters.to.slice(0, 10) : ""}
				onChange={(e) =>
					onChange({
						...filters,
						to: e.target.value ? `${e.target.value}T23:59:59Z` : undefined,
						offset: 0,
					})
				}
				className="bg-zinc-50 dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded-lg px-2.5 py-1.5 text-xs text-zinc-700 dark:text-zinc-300 focus:outline-none focus:ring-2 focus:ring-amber-500/30"
				aria-label="To date"
			/>

			{(filters.agentId ?? filters.action ?? filters.result ?? filters.from ?? filters.to) && (
				<button
					type="button"
					onClick={() => onChange({ limit: filters.limit, offset: 0 })}
					className="text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors ml-auto"
				>
					Clear filters
				</button>
			)}
		</div>
	);
}

// ─── Export Button ────────────────────────────────────────────────────────────

interface ExportButtonProps {
	client: KavachApiClient;
	filters: AuditLogFilters;
}

function ExportButton({ client, filters }: ExportButtonProps) {
	const [open, setOpen] = useState(false);
	const [exporting, setExporting] = useState(false);
	const ref = useRef<HTMLDivElement>(null);

	async function handleExport(format: "json" | "csv") {
		setOpen(false);
		setExporting(true);
		try {
			const result = await client.exportAuditLogs(format, filters);
			if (!result.success) return;
			const blob = new Blob([result.data], {
				type: format === "csv" ? "text/csv" : "application/json",
			});
			const url = URL.createObjectURL(blob);
			const anchor = document.createElement("a");
			anchor.href = url;
			anchor.download = `audit-export.${format}`;
			anchor.click();
			URL.revokeObjectURL(url);
		} finally {
			setExporting(false);
		}
	}

	return (
		<div className="relative" ref={ref}>
			<Button
				variant="secondary"
				size="sm"
				loading={exporting}
				onClick={() => setOpen((v) => !v)}
				aria-haspopup="true"
				aria-expanded={open}
			>
				<Download className="w-3.5 h-3.5" />
				Export
			</Button>
			{open && (
				<div className="absolute right-0 mt-1 w-36 bg-zinc-50 dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded-lg shadow-lg z-10 overflow-hidden">
					<button
						type="button"
						className="w-full text-left px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300 hover:bg-zinc-800 transition-colors"
						onClick={() => void handleExport("json")}
					>
						Export as JSON
					</button>
					<button
						type="button"
						className="w-full text-left px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300 hover:bg-zinc-800 transition-colors"
						onClick={() => void handleExport("csv")}
					>
						Export as CSV
					</button>
				</div>
			)}
		</div>
	);
}

// ─── Audit Log Page ───────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

interface AuditPageProps {
	client: KavachApiClient;
}

export function AuditPage({ client }: AuditPageProps) {
	const [filters, setFilters] = useState<AuditLogFilters>({
		limit: PAGE_SIZE,
		offset: 0,
	});

	const {
		data: logsResult,
		isLoading,
		refetch,
		isFetching,
	} = useQuery({
		queryKey: ["audit-logs", filters],
		queryFn: () => client.getAuditLogs(filters),
		refetchInterval: 30_000, // poll every 30s for real-time feel
	});

	const { data: agentsResult } = useQuery({
		queryKey: ["agents"],
		queryFn: () => client.getAgents(),
	});

	const logs = logsResult?.success ? logsResult.data.entries : [];
	const total = logsResult?.success ? logsResult.data.total : 0;
	const agentOptions = agentsResult?.success
		? agentsResult.data.map((a) => ({ id: a.id, name: a.name }))
		: [];

	const offset = filters.offset ?? 0;
	const limit = filters.limit ?? PAGE_SIZE;
	const hasMore = offset + limit < total;
	const hasPrev = offset > 0;

	return (
		<div>
			<PageHeader
				title="Audit Log"
				description="Immutable record of all agent actions. Compliance-ready."
				actions={
					<>
						<ExportButton client={client} filters={filters} />
						<Button
							variant="secondary"
							size="sm"
							onClick={() => void refetch()}
							loading={isFetching}
						>
							<RefreshCw className="w-3.5 h-3.5" />
							Refresh
						</Button>
					</>
				}
			/>

			<FilterBar filters={filters} agentOptions={agentOptions} onChange={setFilters} />

			{isLoading ? (
				<div className="flex items-center justify-center py-16">
					<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
				</div>
			) : logs.length === 0 ? (
				<Table>
					<TableHead>
						<Th>Timestamp</Th>
						<Th>Agent</Th>
						<Th>Action</Th>
						<Th>Resource</Th>
						<Th>Result</Th>
						<Th>Duration</Th>
					</TableHead>
					<TableBody>
						<tr>
							<td colSpan={6}>
								<EmptyState
									icon={<ScrollText className="w-6 h-6" />}
									title="No audit events yet"
									description="Events are created automatically when agents call kavach.authorize(). Every allow and deny decision is recorded here."
									docsLink="https://theauth.com/docs/audit"
								/>
							</td>
						</tr>
					</TableBody>
				</Table>
			) : (
				<>
					<Table>
						<TableHead>
							<Th>Timestamp</Th>
							<Th>Agent</Th>
							<Th>Action</Th>
							<Th>Resource</Th>
							<Th>Result</Th>
							<Th>Duration</Th>
						</TableHead>
						<TableBody>
							{logs.map((entry) => {
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
											<span className="text-xs text-zinc-500 font-mono">
												{formatDuration(entry.durationMs)}
											</span>
										</Td>
									</Tr>
								);
							})}
						</TableBody>
					</Table>

					{/* Pagination */}
					<div className="flex items-center justify-between mt-4 text-xs text-zinc-500">
						<span>
							{offset + 1}–{Math.min(offset + limit, total)} of {total} entries
						</span>
						<div className="flex items-center gap-2">
							<Button
								variant="secondary"
								size="sm"
								disabled={!hasPrev}
								onClick={() =>
									setFilters((f) => ({
										...f,
										offset: Math.max(0, (f.offset ?? 0) - limit),
									}))
								}
							>
								Previous
							</Button>
							<Button
								variant="secondary"
								size="sm"
								disabled={!hasMore}
								onClick={() => setFilters((f) => ({ ...f, offset: (f.offset ?? 0) + limit }))}
							>
								Next
							</Button>
						</div>
					</div>
				</>
			)}
		</div>
	);
}
