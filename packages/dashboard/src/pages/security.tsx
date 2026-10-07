import { useQuery } from "@tanstack/react-query";
import { Clock, ShieldAlert, ShieldOff, Timer, XCircle } from "lucide-react";
import type { TheAuthApiClient } from "../api/client.js";
import { Badge } from "../components/badge.js";
import { PageHeader } from "../components/layout.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTimestamp(iso: string): string {
	return new Date(iso).toLocaleString("en-US", {
		month: "short",
		day: "numeric",
		hour: "2-digit",
		minute: "2-digit",
		second: "2-digit",
	});
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

interface StatCardProps {
	title: string;
	value: string | number;
	subtitle: string;
	icon: typeof ShieldAlert;
	iconColor: string;
}

function StatCard({ title, value, subtitle, icon: Icon, iconColor }: StatCardProps) {
	return (
		<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 flex flex-col gap-4">
			<div className="flex items-center justify-between">
				<span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">{title}</span>
				<div className={`w-8 h-8 rounded-lg flex items-center justify-center ${iconColor}`}>
					<Icon className="w-4 h-4 text-zinc-900 dark:text-white" strokeWidth={2} />
				</div>
			</div>
			<div>
				<p className="text-3xl font-semibold text-zinc-900 dark:text-white tracking-tight">
					{value}
				</p>
				<p className="text-xs text-zinc-500 mt-1">{subtitle}</p>
			</div>
		</div>
	);
}

function SkeletonCard() {
	return (
		<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 flex flex-col gap-4 animate-pulse">
			<div className="flex items-center justify-between">
				<div className="h-3 w-24 bg-zinc-200 dark:bg-zinc-800 rounded" />
				<div className="w-8 h-8 bg-zinc-200 dark:bg-zinc-800 rounded-lg" />
			</div>
			<div>
				<div className="h-8 w-16 bg-zinc-200 dark:bg-zinc-800 rounded" />
				<div className="h-3 w-28 bg-zinc-200 dark:bg-zinc-800 rounded mt-2" />
			</div>
		</div>
	);
}

// ─── Security Page ────────────────────────────────────────────────────────────

interface SecurityPageProps {
	client: TheAuthApiClient;
}

export function SecurityPage({ client }: SecurityPageProps) {
	const { data: statsResult, isLoading: statsLoading } = useQuery({
		queryKey: ["dashboard", "stats"],
		queryFn: () => client.getStats(),
		refetchInterval: 30_000,
	});

	const { data: agentsResult } = useQuery({
		queryKey: ["agents"],
		queryFn: () => client.getAgents(),
	});

	const { data: denialsResult, isLoading: denialsLoading } = useQuery({
		queryKey: ["audit-denials"],
		queryFn: () => client.getAuditLogs({ result: "denied", limit: 20 }),
		refetchInterval: 30_000,
	});

	const { data: rateLimitedResult, isLoading: rateLimitedLoading } = useQuery({
		queryKey: ["audit-rate-limited"],
		queryFn: () => client.getAuditLogs({ result: "rate_limited", limit: 20 }),
		refetchInterval: 30_000,
	});

	const stats = statsResult?.success ? statsResult.data : null;
	const agents = agentsResult?.success ? agentsResult.data : [];
	const denials = denialsResult?.success ? denialsResult.data.entries : [];
	const rateLimited = rateLimitedResult?.success ? rateLimitedResult.data.entries : [];

	const revokedCount = agents.filter((a) => a.status === "revoked").length;
	const expiredCount = agents.filter((a) => a.status === "expired").length;

	// Unique agents that hit rate limits recently
	const rateLimitedAgentIds = [...new Set(rateLimited.map((e) => e.agentId))];
	const rateLimitedAgents = rateLimitedAgentIds.map((id) => {
		const entry = rateLimited.find((e) => e.agentId === id);
		return { id, name: entry?.agentName ?? id };
	});

	return (
		<div>
			<PageHeader
				title="Security"
				description="Security health, denied access attempts, and rate limiting overview."
			/>

			{/* Stats */}
			<div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
				{statsLoading || !stats ? (
					<>
						<SkeletonCard />
						<SkeletonCard />
						<SkeletonCard />
						<SkeletonCard />
					</>
				) : (
					<>
						<StatCard
							title="Rate limited (24h)"
							value={rateLimitedResult?.success ? rateLimitedResult.data.total : "—"}
							subtitle="requests throttled in last 24h"
							icon={Timer}
							iconColor="bg-amber-600"
						/>
						<StatCard
							title="Denied (24h)"
							value={denialsResult?.success ? denialsResult.data.total : "—"}
							subtitle="access denied events in last 24h"
							icon={XCircle}
							iconColor="bg-red-600"
						/>
						<StatCard
							title="Revoked agents"
							value={revokedCount}
							subtitle="agents manually revoked"
							icon={ShieldOff}
							iconColor="bg-rose-700"
						/>
						<StatCard
							title="Expired tokens"
							value={expiredCount}
							subtitle="agents with expired credentials"
							icon={ShieldAlert}
							iconColor="bg-zinc-600"
						/>
					</>
				)}
			</div>

			<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
				{/* Recent denials */}
				<div className="lg:col-span-2">
					<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden">
						<div className="px-5 py-4 border-b border-zinc-200 dark:border-zinc-800">
							<h2 className="text-sm font-semibold text-zinc-900 dark:text-white">
								Recent denials
							</h2>
							<p className="text-xs text-zinc-500 mt-0.5">Last 20 denied access events</p>
						</div>

						{denialsLoading ? (
							<div className="flex items-center justify-center py-12">
								<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
							</div>
						) : denials.length === 0 ? (
							<div className="flex flex-col items-center justify-center py-12 text-center">
								<div className="w-10 h-10 rounded-xl bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center mb-3 text-zinc-500">
									<XCircle className="w-5 h-5" />
								</div>
								<p className="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">
									No denied events
								</p>
								<p className="text-xs text-zinc-500">All recent access requests were allowed.</p>
							</div>
						) : (
							<Table>
								<TableHead>
									<Th>Timestamp</Th>
									<Th>Agent</Th>
									<Th>Action</Th>
									<Th>Resource</Th>
								</TableHead>
								<TableBody>
									{denials.map((entry) => (
										<Tr key={entry.id}>
											<Td>
												<div className="flex items-center gap-1.5">
													<Clock className="w-3 h-3 text-zinc-600 flex-shrink-0" />
													<span className="text-xs text-zinc-700 dark:text-zinc-300 font-mono">
														{formatTimestamp(entry.timestamp)}
													</span>
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
												<code className="text-xs font-mono text-zinc-400 max-w-[180px] truncate block">
													{entry.resource}
												</code>
											</Td>
										</Tr>
									))}
								</TableBody>
							</Table>
						)}
					</div>
				</div>

				{/* Rate limited agents */}
				<div>
					<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden">
						<div className="px-5 py-4 border-b border-zinc-200 dark:border-zinc-800">
							<h2 className="text-sm font-semibold text-zinc-900 dark:text-white">
								Rate limited agents
							</h2>
							<p className="text-xs text-zinc-500 mt-0.5">Agents hitting limits recently</p>
						</div>

						{rateLimitedLoading ? (
							<div className="flex items-center justify-center py-10">
								<div className="w-4 h-4 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
							</div>
						) : rateLimitedAgents.length === 0 ? (
							<div className="flex flex-col items-center justify-center py-10 text-center px-4">
								<EmptyState
									icon={<Timer className="w-5 h-5" />}
									title="No throttled agents"
									description="No agents have hit rate limits recently."
								/>
							</div>
						) : (
							<div className="divide-y divide-zinc-800/60">
								{rateLimitedAgents.map((agent) => {
									const hitCount = rateLimited.filter((e) => e.agentId === agent.id).length;
									return (
										<div key={agent.id} className="flex items-center justify-between px-5 py-3.5">
											<div>
												<p className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
													{agent.name}
												</p>
												<p className="text-[11px] font-mono text-zinc-600 mt-0.5">
													{agent.id.slice(0, 12)}…
												</p>
											</div>
											<Badge variant="yellow">{hitCount} hits</Badge>
										</div>
									);
								})}
							</div>
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
