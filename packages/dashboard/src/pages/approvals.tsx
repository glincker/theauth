import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, ListChecks, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type { PendingApproval } from "../api/types.js";
import { Button } from "../components/button.js";
import { PageHeader } from "../components/layout.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";
import { useToast } from "../components/toast.js";

const POLL_MS = 15_000;

type Decision = "approve" | "deny";

/** "4m 05s", "45s", or "expired" for a past timestamp. */
/** The approvals routes are opt in on the server; a 404 means they are not mounted, not that loading broke. */
export function approvalsUnavailable(error: { code: string }): boolean {
	return error.code === "HTTP_404";
}

export function formatExpiresIn(iso: string, now: number): string {
	const secs = Math.floor((new Date(iso).getTime() - now) / 1000);
	if (secs <= 0) return "expired";
	if (secs < 60) return `${secs}s`;
	const m = Math.floor(secs / 60);
	if (m < 60) return `${m}m ${String(secs % 60).padStart(2, "0")}s`;
	return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

function prettyArguments(raw: string, truncated: boolean): string {
	if (truncated) return `${raw}\n... (truncated)`;
	try {
		return JSON.stringify(JSON.parse(raw), null, 2);
	} catch {
		return raw;
	}
}

interface RowProps {
	approval: PendingApproval;
	now: number;
	expanded: boolean;
	confirming: Decision | null;
	busy: boolean;
	onToggle: () => void;
	onAsk: (decision: Decision | null) => void;
	onConfirm: (decision: Decision) => void;
}

function ApprovalRow({
	approval,
	now,
	expanded,
	confirming,
	busy,
	onToggle,
	onAsk,
	onConfirm,
}: RowProps) {
	const argsId = `approval-args-${approval.id}`;
	const Chevron = expanded ? ChevronDown : ChevronRight;
	return (
		<>
			<Tr>
				<Td>
					<code className="text-xs font-mono text-zinc-700 dark:text-zinc-300">
						{approval.action}
					</code>
				</Td>
				<Td>
					<code className="text-xs font-mono text-zinc-400 max-w-[220px] truncate block">
						{approval.resource}
					</code>
				</Td>
				<Td>
					<span className="text-xs text-zinc-700 dark:text-zinc-300">{approval.requestedBy}</span>
				</Td>
				<Td>
					<span className="text-xs font-mono text-zinc-500">
						{formatExpiresIn(approval.expiresAt, now)}
					</span>
				</Td>
				<Td>
					<button
						type="button"
						onClick={onToggle}
						aria-expanded={expanded}
						aria-controls={argsId}
						aria-label={`${expanded ? "Hide" : "Show"} arguments for ${approval.action} on ${approval.resource}`}
						className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/30"
					>
						<Chevron className="w-3.5 h-3.5" aria-hidden="true" />
						Arguments
					</button>
				</Td>
				<Td>
					{confirming ? (
						<div className="flex items-center gap-2">
							<span className="text-xs text-zinc-500">
								{confirming === "approve" ? "Approve this request?" : "Deny this request?"}
							</span>
							<Button
								size="sm"
								variant={confirming === "approve" ? "primary" : "danger"}
								loading={busy}
								onClick={() => onConfirm(confirming)}
								aria-label={`Confirm ${confirming} ${approval.action} on ${approval.resource}`}
								autoFocus
							>
								Confirm
							</Button>
							<Button size="sm" variant="ghost" disabled={busy} onClick={() => onAsk(null)}>
								Cancel
							</Button>
						</div>
					) : (
						<div className="flex items-center gap-2">
							<Button
								size="sm"
								variant="primary"
								onClick={() => onAsk("approve")}
								aria-label={`Approve ${approval.action} on ${approval.resource}`}
							>
								Approve
							</Button>
							<Button
								size="sm"
								variant="danger"
								onClick={() => onAsk("deny")}
								aria-label={`Deny ${approval.action} on ${approval.resource}`}
							>
								Deny
							</Button>
						</div>
					)}
				</Td>
			</Tr>
			{expanded && (
				<tr id={argsId}>
					<td colSpan={6} className="px-4 pb-3">
						<pre className="text-xs font-mono text-zinc-600 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg p-3 overflow-auto max-h-64 whitespace-pre-wrap break-all">
							{prettyArguments(approval.arguments, approval.argumentsTruncated)}
						</pre>
					</td>
				</tr>
			)}
		</>
	);
}

interface ApprovalsPageProps {
	client: TheAuthApiClient;
}

export function ApprovalsPage({ client }: ApprovalsPageProps) {
	const queryClient = useQueryClient();
	const { toast } = useToast();
	const [now, setNow] = useState(() => Date.now());
	const [expandedId, setExpandedId] = useState<string | null>(null);
	const [confirm, setConfirm] = useState<{ id: string; decision: Decision } | null>(null);

	useEffect(() => {
		const timer = setInterval(() => setNow(Date.now()), 1000);
		return () => clearInterval(timer);
	}, []);

	const { data, isLoading, isFetching, refetch } = useQuery({
		queryKey: ["approvals", "pending"],
		queryFn: () => client.getPendingApprovals(),
		refetchInterval: POLL_MS,
	});

	const decide = useMutation({
		mutationFn: (v: { id: string; decision: Decision }) => client.decideApproval(v.id, v.decision),
		onSuccess: (result, v) => {
			setConfirm(null);
			if (result.success) {
				toast("success", v.decision === "approve" ? "Request approved" : "Request denied");
			} else {
				toast("error", result.error.message);
			}
			void queryClient.invalidateQueries({ queryKey: ["approvals"] });
		},
		onError: () => toast("error", "Decision failed"),
	});

	const rows = data?.success ? data.data : [];
	const failed = data !== undefined && !data.success;

	return (
		<div>
			<PageHeader
				title="Approvals"
				description="Admin requests waiting for a second person. You cannot decide a request you opened."
				actions={
					<Button variant="secondary" size="sm" onClick={() => void refetch()} loading={isFetching}>
						<RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
						Refresh
					</Button>
				}
			/>

			{failed && (
				<div
					role="alert"
					className="mb-4 rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-400"
				>
					{approvalsUnavailable(data.error)
						? "The approvals API is not enabled on this server. Turn on adminApi to use the inbox."
						: `Could not load approvals: ${data.error.message}`}
				</div>
			)}

			{isLoading ? (
				<div className="flex items-center justify-center py-16" role="status">
					<span className="sr-only">Loading approvals</span>
					<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
				</div>
			) : (
				<Table>
					<TableHead>
						<Th>Action</Th>
						<Th>Resource</Th>
						<Th>Requested by</Th>
						<Th>Expires in</Th>
						<Th>Details</Th>
						<Th>Decision</Th>
					</TableHead>
					<TableBody>
						{rows.length === 0 ? (
							<tr>
								<td colSpan={6}>
									<EmptyState
										icon={<ListChecks className="w-6 h-6" />}
										title="No pending approvals"
										description="Requests opened by the admin MCP server appear here until they are decided or expire."
									/>
								</td>
							</tr>
						) : (
							rows.map((a) => (
								<ApprovalRow
									key={a.id}
									approval={a}
									now={now}
									expanded={expandedId === a.id}
									confirming={confirm?.id === a.id ? confirm.decision : null}
									busy={decide.isPending && decide.variables?.id === a.id}
									onToggle={() => setExpandedId((cur) => (cur === a.id ? null : a.id))}
									onAsk={(decision) => setConfirm(decision ? { id: a.id, decision } : null)}
									onConfirm={(decision) => decide.mutate({ id: a.id, decision })}
								/>
							))
						)}
					</TableBody>
				</Table>
			)}
		</div>
	);
}
