import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	ArrowRight,
	Bot,
	Check,
	Clock,
	Copy,
	MoreHorizontal,
	Plus,
	RotateCw,
	ShieldOff,
} from "lucide-react";
import { useState } from "react";
import type { KavachApiClient } from "../api/client.js";
import type { Agent, AgentType, AuditResult, CreateAgentInput } from "../api/types.js";
import { Badge, StatusDot } from "../components/badge.js";
import { Button } from "../components/button.js";
import { FormGroup, Input, Label, Select } from "../components/input.js";
import { PageHeader } from "../components/layout.js";
import { Modal } from "../components/modal.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";
import { useToast } from "../components/toast.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusVariant(status: Agent["status"]) {
	switch (status) {
		case "active":
			return "green" as const;
		case "revoked":
			return "red" as const;
		case "expired":
			return "gray" as const;
	}
}

function formatDate(iso: string | null) {
	if (!iso) return "—";
	return new Date(iso).toLocaleDateString("en-US", {
		month: "short",
		day: "numeric",
		year: "numeric",
	});
}

function formatRelative(iso: string | null) {
	if (!iso) return "Never";
	const diff = Date.now() - new Date(iso).getTime();
	const mins = Math.floor(diff / 60_000);
	if (mins < 1) return "Just now";
	if (mins < 60) return `${mins}m ago`;
	const hours = Math.floor(mins / 60);
	if (hours < 24) return `${hours}h ago`;
	const days = Math.floor(hours / 24);
	return `${days}d ago`;
}

const AGENT_TYPES: AgentType[] = ["llm", "workflow", "tool", "human-in-loop", "system"];

// ─── Create Agent Modal ───────────────────────────────────────────────────────

interface CreateAgentModalProps {
	open: boolean;
	onClose: () => void;
	onSubmit: (input: CreateAgentInput) => void;
	loading: boolean;
}

function CreateAgentModal({ open, onClose, onSubmit, loading }: CreateAgentModalProps) {
	const [name, setName] = useState("");
	const [type, setType] = useState<AgentType>("llm");
	const [resource, setResource] = useState("");
	const [actions, setActions] = useState<string[]>([]);
	const [nameError, setNameError] = useState("");

	const COMMON_ACTIONS = ["read", "write", "delete", "execute", "list"];

	function toggleAction(action: string) {
		setActions((prev) =>
			prev.includes(action) ? prev.filter((a) => a !== action) : [...prev, action],
		);
	}

	function handleSubmit() {
		if (!name.trim()) {
			setNameError("Name is required");
			return;
		}
		setNameError("");

		const permissions =
			resource.trim() && actions.length > 0 ? [{ resource: resource.trim(), actions }] : [];

		onSubmit({ name: name.trim(), type, permissions });
	}

	function handleClose() {
		setName("");
		setType("llm");
		setResource("");
		setActions([]);
		setNameError("");
		onClose();
	}

	return (
		<Modal
			open={open}
			onClose={handleClose}
			title="Create Agent"
			footer={
				<>
					<Button variant="ghost" onClick={handleClose}>
						Cancel
					</Button>
					<Button variant="primary" onClick={handleSubmit} loading={loading}>
						Create Agent
					</Button>
				</>
			}
		>
			<div className="space-y-4">
				<FormGroup>
					<Label htmlFor="agent-name" required>
						Name
					</Label>
					<Input
						id="agent-name"
						placeholder="e.g. data-pipeline-agent"
						value={name}
						onChange={(e) => setName(e.target.value)}
						error={nameError}
						autoFocus
					/>
				</FormGroup>

				<FormGroup>
					<Label htmlFor="agent-type" required>
						Type
					</Label>
					<Select
						id="agent-type"
						value={type}
						onChange={(e) => setType(e.target.value as AgentType)}
					>
						{AGENT_TYPES.map((t) => (
							<option key={t} value={t}>
								{t}
							</option>
						))}
					</Select>
				</FormGroup>

				<div className="border-t border-zinc-200 dark:border-zinc-800 pt-4">
					<p className="text-xs font-medium text-zinc-400 mb-3">Initial Permission (optional)</p>

					<FormGroup>
						<Label htmlFor="resource">Resource Pattern</Label>
						<Input
							id="resource"
							placeholder="e.g. documents:* or api/v1/users"
							value={resource}
							onChange={(e) => setResource(e.target.value)}
						/>
					</FormGroup>

					<div className="mt-3">
						<Label>Actions</Label>
						<div className="flex flex-wrap gap-2 mt-1.5">
							{COMMON_ACTIONS.map((action) => (
								<button
									key={action}
									type="button"
									onClick={() => toggleAction(action)}
									className={[
										"px-2.5 py-1 rounded-md text-xs font-medium border transition-colors",
										actions.includes(action)
											? "bg-amber-600 border-amber-500 text-white"
											: "bg-zinc-100 dark:bg-zinc-800 border-zinc-300 dark:border-zinc-700 text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200",
									].join(" ")}
								>
									{action}
								</button>
							))}
						</div>
					</div>
				</div>
			</div>
		</Modal>
	);
}

// ─── Token Display Modal ──────────────────────────────────────────────────────

interface TokenModalProps {
	open: boolean;
	onClose: () => void;
	token: string;
	agentName: string;
}

function TokenModal({ open, onClose, token, agentName }: TokenModalProps) {
	const [copied, setCopied] = useState(false);

	function copyToken() {
		void navigator.clipboard.writeText(token).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		});
	}

	return (
		<Modal
			open={open}
			onClose={onClose}
			title="Agent Token"
			footer={
				<Button variant="primary" onClick={onClose}>
					Done
				</Button>
			}
		>
			<div className="space-y-4">
				<div className="bg-amber-950/50 border border-amber-800/50 rounded-lg px-4 py-3">
					<p className="text-xs text-amber-400 font-medium">
						Save this token now. It will not be shown again.
					</p>
				</div>
				<div>
					<Label>Agent</Label>
					<p className="text-sm text-zinc-300">{agentName}</p>
				</div>
				<div>
					<Label>Token</Label>
					<div className="flex items-center gap-2 mt-1.5">
						<code className="flex-1 bg-white dark:bg-zinc-950 border border-zinc-300 dark:border-zinc-700 rounded-lg px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300 font-mono break-all">
							{token}
						</code>
						<button
							type="button"
							onClick={copyToken}
							className="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-lg bg-zinc-100 dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 text-zinc-400 hover:text-zinc-200 transition-colors"
							aria-label="Copy token"
						>
							{copied ? (
								<Check className="w-3.5 h-3.5 text-emerald-400" />
							) : (
								<Copy className="w-3.5 h-3.5" />
							)}
						</button>
					</div>
				</div>
			</div>
		</Modal>
	);
}

// ─── Agent Row Actions ────────────────────────────────────────────────────────

interface AgentActionsProps {
	agent: Agent;
	onRevoke: (id: string) => void;
	onRotate: (id: string) => void;
	revoking: boolean;
	rotating: boolean;
}

function AgentActions({ agent, onRevoke, onRotate, revoking, rotating }: AgentActionsProps) {
	const [open, setOpen] = useState(false);

	if (agent.status !== "active") return null;

	return (
		<div className="relative">
			<button
				type="button"
				onClick={() => setOpen((v) => !v)}
				className="w-7 h-7 flex items-center justify-center rounded-md text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 hover:bg-zinc-800 transition-colors"
				aria-label="Agent actions"
			>
				<MoreHorizontal className="w-4 h-4" />
			</button>

			{open && (
				<>
					<div className="fixed inset-0 z-10" onClick={() => setOpen(false)} aria-hidden="true" />
					<div className="absolute right-0 top-8 z-20 bg-zinc-50 dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded-xl shadow-xl py-1 min-w-[140px]">
						<button
							type="button"
							onClick={() => {
								onRotate(agent.id);
								setOpen(false);
							}}
							disabled={rotating}
							className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300 hover:bg-zinc-800 hover:text-white transition-colors disabled:opacity-50"
						>
							<RotateCw className="w-3.5 h-3.5" />
							Rotate Token
						</button>
						<div className="border-t border-zinc-200 dark:border-zinc-800 my-1" />
						<button
							type="button"
							onClick={() => {
								onRevoke(agent.id);
								setOpen(false);
							}}
							disabled={revoking}
							className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-red-400 hover:bg-red-950/50 hover:text-red-300 transition-colors disabled:opacity-50"
						>
							<ShieldOff className="w-3.5 h-3.5" />
							Revoke Agent
						</button>
					</div>
				</>
			)}
		</div>
	);
}

// ─── Agent Detail Modal ───────────────────────────────────────────────────────

function resultVariant(result: AuditResult): "green" | "red" | "yellow" {
	switch (result) {
		case "allowed":
			return "green";
		case "denied":
			return "red";
		case "rate_limited":
			return "yellow";
	}
}

function formatTimestamp(iso: string): string {
	return new Date(iso).toLocaleString("en-US", {
		month: "short",
		day: "numeric",
		hour: "2-digit",
		minute: "2-digit",
		second: "2-digit",
	});
}

interface AgentDetailModalProps {
	open: boolean;
	onClose: () => void;
	agent: Agent;
	client: KavachApiClient;
}

function AgentDetailModal({ open, onClose, agent, client }: AgentDetailModalProps) {
	const { data: permissionsResult, isLoading: permLoading } = useQuery({
		queryKey: ["agent-permissions", agent.id],
		queryFn: () => client.getAgentPermissions(agent.id),
		enabled: open,
	});

	const { data: auditResult, isLoading: auditLoading } = useQuery({
		queryKey: ["agent-audit", agent.id],
		queryFn: () => client.getAuditLogs({ agentId: agent.id, limit: 20 }),
		enabled: open,
	});

	const { data: delegationsResult } = useQuery({
		queryKey: ["delegations"],
		queryFn: () => client.getDelegations(),
		enabled: open,
	});

	const permissions = permissionsResult?.success ? permissionsResult.data : [];
	const auditEntries = auditResult?.success ? auditResult.data.entries : [];
	const allDelegations = delegationsResult?.success ? delegationsResult.data : [];
	const agentDelegations = allDelegations.filter(
		(d) => d.fromAgentId === agent.id || d.toAgentId === agent.id,
	);

	return (
		<Modal
			open={open}
			onClose={onClose}
			title={agent.name}
			footer={
				<Button variant="primary" onClick={onClose}>
					Close
				</Button>
			}
		>
			<div className="space-y-6">
				{/* Agent info */}
				<div className="grid grid-cols-2 gap-x-6 gap-y-3">
					<div>
						<p className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-1">
							ID
						</p>
						<code className="text-xs font-mono text-zinc-700 dark:text-zinc-300 break-all">
							{agent.id}
						</code>
					</div>
					<div>
						<p className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-1">
							Type
						</p>
						<span className="text-xs font-mono text-zinc-300">{agent.type}</span>
					</div>
					<div>
						<p className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-1">
							Status
						</p>
						<Badge variant={statusVariant(agent.status)}>
							<StatusDot variant={statusVariant(agent.status)} />
							{agent.status}
						</Badge>
					</div>
					<div>
						<p className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-1">
							Last active
						</p>
						<span className="text-xs text-zinc-300">{formatRelative(agent.lastActiveAt)}</span>
					</div>
					<div>
						<p className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-1">
							Created
						</p>
						<span className="text-xs text-zinc-300">{formatDate(agent.createdAt)}</span>
					</div>
					<div>
						<p className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-1">
							Expires
						</p>
						<span className="text-xs text-zinc-300">{formatDate(agent.expiresAt)}</span>
					</div>
				</div>

				{/* Permissions */}
				<div>
					<p className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">
						Permissions
					</p>
					{permLoading ? (
						<div className="flex items-center justify-center py-4">
							<div className="w-4 h-4 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
						</div>
					) : permissions.length === 0 ? (
						<p className="text-xs text-zinc-600 py-2">No permissions assigned.</p>
					) : (
						<div className="rounded-lg border border-zinc-200 dark:border-zinc-800 overflow-hidden">
							<table className="w-full text-xs">
								<thead className="bg-zinc-50 dark:bg-zinc-900 border-b border-zinc-200 dark:border-zinc-800">
									<tr>
										<th className="px-3 py-2 text-left text-[11px] font-medium text-zinc-500 uppercase tracking-wider">
											Resource
										</th>
										<th className="px-3 py-2 text-left text-[11px] font-medium text-zinc-500 uppercase tracking-wider">
											Actions
										</th>
									</tr>
								</thead>
								<tbody className="divide-y divide-zinc-800/60">
									{permissions.map((p) => (
										<tr key={p.id} className="bg-zinc-950">
											<td className="px-3 py-2">
												<code className="text-zinc-300 font-mono">{p.resource}</code>
											</td>
											<td className="px-3 py-2">
												<div className="flex flex-wrap gap-1">
													{p.actions.map((a) => (
														<span
															key={a}
															className="px-1.5 py-0.5 bg-zinc-100 dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 rounded text-[10px] text-zinc-400 font-mono"
														>
															{a}
														</span>
													))}
												</div>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</div>

				{/* Delegation chains */}
				{agentDelegations.length > 0 && (
					<div>
						<p className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">
							Delegation chains
						</p>
						<div className="space-y-2">
							{agentDelegations.map((d) => (
								<div
									key={d.id}
									className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs"
								>
									<span className="text-zinc-300 font-medium truncate max-w-[100px]">
										{d.fromAgentName}
									</span>
									<ArrowRight className="w-3 h-3 text-zinc-600 flex-shrink-0" />
									<span className="text-zinc-300 font-medium truncate max-w-[100px]">
										{d.toAgentName}
									</span>
									<Badge
										variant={
											d.status === "active" ? "green" : d.status === "expired" ? "yellow" : "red"
										}
									>
										{d.status}
									</Badge>
								</div>
							))}
						</div>
					</div>
				)}

				{/* Recent audit activity */}
				<div>
					<p className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">
						Recent activity
					</p>
					{auditLoading ? (
						<div className="flex items-center justify-center py-4">
							<div className="w-4 h-4 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
						</div>
					) : auditEntries.length === 0 ? (
						<p className="text-xs text-zinc-600 py-2">No audit events yet.</p>
					) : (
						<div className="rounded-lg border border-zinc-200 dark:border-zinc-800 overflow-hidden">
							<div className="divide-y divide-zinc-800/60">
								{auditEntries.map((entry) => (
									<div
										key={entry.id}
										className="flex items-center gap-3 px-3 py-2.5 bg-white dark:bg-zinc-950 text-xs"
									>
										<Clock className="w-3 h-3 text-zinc-600 flex-shrink-0" />
										<span className="text-zinc-500 tabular-nums flex-shrink-0 w-28">
											{formatTimestamp(entry.timestamp)}
										</span>
										<code className="text-zinc-400 font-mono w-20 flex-shrink-0 truncate">
											{entry.action}
										</code>
										<code className="text-zinc-500 font-mono flex-1 truncate">
											{entry.resource}
										</code>
										<Badge variant={resultVariant(entry.result)}>
											{entry.result.replace("_", " ")}
										</Badge>
									</div>
								))}
							</div>
						</div>
					)}
				</div>
			</div>
		</Modal>
	);
}

// ─── Agents Page ──────────────────────────────────────────────────────────────

interface AgentsPageProps {
	client: KavachApiClient;
}

export function AgentsPage({ client }: AgentsPageProps) {
	const queryClient = useQueryClient();
	const { toast } = useToast();
	const [createOpen, setCreateOpen] = useState(false);
	const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
	const [tokenModal, setTokenModal] = useState<{
		open: boolean;
		token: string;
		agentName: string;
	}>({ open: false, token: "", agentName: "" });

	const { data: agentsResult, isLoading } = useQuery({
		queryKey: ["agents"],
		queryFn: () => client.getAgents(),
	});

	const createMutation = useMutation({
		mutationFn: (input: CreateAgentInput) => client.createAgent(input),
		onSuccess: (result) => {
			if (result.success) {
				void queryClient.invalidateQueries({ queryKey: ["agents"] });
				setCreateOpen(false);
				toast("success", `Agent "${result.data.agent.name}" created`);
				setTokenModal({
					open: true,
					token: result.data.token,
					agentName: result.data.agent.name,
				});
			} else {
				toast("error", "Failed to create agent");
			}
		},
		onError: () => {
			toast("error", "Failed to create agent");
		},
	});

	const revokeMutation = useMutation({
		mutationFn: (agentId: string) => client.revokeAgent(agentId),
		onSuccess: (result, agentId) => {
			void queryClient.invalidateQueries({ queryKey: ["agents"] });
			if (result.success) {
				const agents = agentsResult?.success ? agentsResult.data : [];
				const agent = agents.find((a) => a.id === agentId);
				toast("success", `Agent "${agent?.name ?? "Agent"}" revoked`);
			} else {
				toast("error", "Failed to revoke agent");
			}
		},
		onError: () => {
			toast("error", "Failed to revoke agent");
		},
	});

	const rotateMutation = useMutation({
		mutationFn: (agentId: string) => client.rotateAgentToken(agentId),
		onSuccess: (result, agentId) => {
			if (result.success) {
				const agents = agentsResult?.success ? agentsResult.data : [];
				const agent = agents.find((a) => a.id === agentId);
				toast("success", `Token rotated for "${agent?.name ?? "Agent"}"`);
				setTokenModal({
					open: true,
					token: result.data.token,
					agentName: agent?.name ?? "Agent",
				});
			} else {
				toast("error", "Failed to rotate token");
			}
		},
		onError: () => {
			toast("error", "Failed to rotate token");
		},
	});

	const agents = agentsResult?.success ? agentsResult.data : [];

	return (
		<div>
			<PageHeader
				title="Agents"
				description="Manage AI agent identities, tokens, and permissions."
				actions={
					<Button variant="primary" onClick={() => setCreateOpen(true)}>
						<Plus className="w-3.5 h-3.5" />
						New Agent
					</Button>
				}
			/>

			{isLoading ? (
				<div className="flex items-center justify-center py-16">
					<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
				</div>
			) : agents.length === 0 ? (
				<Table>
					<TableHead>
						<Th>Agent</Th>
						<Th>Type</Th>
						<Th>Status</Th>
						<Th>Permissions</Th>
						<Th>Last Active</Th>
						<Th>Created</Th>
						<Th />
					</TableHead>
					<TableBody>
						<tr>
							<td colSpan={7}>
								<EmptyState
									icon={<Bot className="w-6 h-6" />}
									title="Create your first agent"
									description="Agents are the primary identity in TheAuth. Each agent gets a token you use to authorize actions."
									steps={[
										'Click "New Agent" above',
										"Set permissions for the resources the agent needs",
										"Copy the token and use it in your app",
									]}
									action={
										<Button variant="primary" onClick={() => setCreateOpen(true)}>
											<Plus className="w-3.5 h-3.5" />
											Create Agent
										</Button>
									}
									docsLink="https://theauth.dev/docs/quickstart"
								/>
							</td>
						</tr>
					</TableBody>
				</Table>
			) : (
				<Table>
					<TableHead>
						<Th>Agent</Th>
						<Th>Type</Th>
						<Th>Status</Th>
						<Th>Permissions</Th>
						<Th>Last Active</Th>
						<Th>Created</Th>
						<Th />
					</TableHead>
					<TableBody>
						{agents.map((agent) => (
							<Tr key={agent.id} onClick={() => setSelectedAgent(agent)}>
								<Td>
									<div>
										<p className="text-sm font-medium text-white">{agent.name}</p>
										<p className="text-xs text-zinc-500 font-mono mt-0.5">
											{agent.id.slice(0, 12)}…
										</p>
									</div>
								</Td>
								<Td>
									<span className="text-xs font-mono text-zinc-400">{agent.type}</span>
								</Td>
								<Td>
									<Badge variant={statusVariant(agent.status)}>
										<StatusDot variant={statusVariant(agent.status)} />
										{agent.status}
									</Badge>
								</Td>
								<Td>
									<span className="text-zinc-300">{agent.permissionsCount}</span>
								</Td>
								<Td>
									<span className="text-zinc-400 text-xs">
										{formatRelative(agent.lastActiveAt)}
									</span>
								</Td>
								<Td>
									<span className="text-zinc-400 text-xs">{formatDate(agent.createdAt)}</span>
								</Td>
								<Td className="text-right">
									<AgentActions
										agent={agent}
										onRevoke={(id) => revokeMutation.mutate(id)}
										onRotate={(id) => rotateMutation.mutate(id)}
										revoking={revokeMutation.isPending}
										rotating={rotateMutation.isPending}
									/>
								</Td>
							</Tr>
						))}
					</TableBody>
				</Table>
			)}

			<CreateAgentModal
				open={createOpen}
				onClose={() => setCreateOpen(false)}
				onSubmit={(input) => createMutation.mutate(input)}
				loading={createMutation.isPending}
			/>

			<TokenModal
				open={tokenModal.open}
				onClose={() => setTokenModal({ open: false, token: "", agentName: "" })}
				token={tokenModal.token}
				agentName={tokenModal.agentName}
			/>

			{selectedAgent && (
				<AgentDetailModal
					open={selectedAgent !== null}
					onClose={() => setSelectedAgent(null)}
					agent={selectedAgent}
					client={client}
				/>
			)}
		</div>
	);
}
