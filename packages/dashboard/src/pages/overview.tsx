import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Bot, CalendarClock, ShieldCheck, Users } from "lucide-react";
import { useEffect } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type { AuditResult } from "../api/types.js";
import { Badge } from "../components/badge.js";
import { PageHeader } from "../components/layout.js";
import type { Page } from "../types.js";

// ─── Types ────────────────────────────────────────────────────────────────────

interface OverviewPageProps {
	client: TheAuthApiClient;
	onNavigate: (page: Page) => void;
}

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

function resultLabel(result: AuditResult): string {
	switch (result) {
		case "allowed":
			return "allowed";
		case "denied":
			return "denied";
		case "rate_limited":
			return "rate limited";
	}
}

// ─── Stats Card ───────────────────────────────────────────────────────────────

interface StatCardProps {
	title: string;
	value: string | number;
	subtitle: string;
	icon: typeof Bot;
	iconColor: string;
}

function StatCard({ title, value, subtitle, icon: Icon, iconColor }: StatCardProps) {
	return (
		<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 flex flex-col gap-4">
			<div className="flex items-center justify-between">
				<span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
					{title}
				</span>
				<div className={`w-8 h-8 rounded-lg flex items-center justify-center ${iconColor}`}>
					<Icon className="w-4 h-4 text-zinc-900 dark:text-white" strokeWidth={2} />
				</div>
			</div>
			<div>
				<p className="text-3xl font-semibold text-zinc-900 dark:text-white tracking-tight">
					{value}
				</p>
				<p className="text-xs text-zinc-500 dark:text-zinc-500 mt-1">{subtitle}</p>
			</div>
		</div>
	);
}

// ─── Loading Skeleton ─────────────────────────────────────────────────────────

function SkeletonCard() {
	return (
		<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5 flex flex-col gap-4 animate-pulse">
			<div className="flex items-center justify-between">
				<div className="h-3 w-24 bg-zinc-200 dark:bg-zinc-800 rounded" />
				<div className="w-8 h-8 bg-zinc-200 dark:bg-zinc-200 dark:bg-zinc-800 rounded-lg" />
			</div>
			<div>
				<div className="h-8 w-16 bg-zinc-200 dark:bg-zinc-800 rounded" />
				<div className="h-3 w-28 bg-zinc-200 dark:bg-zinc-800 rounded mt-2" />
			</div>
		</div>
	);
}

// ─── Activity Feed ────────────────────────────────────────────────────────────

interface ActivityFeedProps {
	client: TheAuthApiClient;
}

function ActivityFeed({ client }: ActivityFeedProps) {
	const {
		data: auditResult,
		isLoading,
		dataUpdatedAt,
	} = useQuery({
		queryKey: ["audit", "recent"],
		queryFn: () => client.getAuditLogs({ limit: 10 }),
		refetchInterval: 15_000,
	});

	const entries = auditResult?.success ? auditResult.data.entries : [];
	const lastUpdated = dataUpdatedAt > 0 ? new Date(dataUpdatedAt) : null;

	return (
		<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden">
			<div className="px-5 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
				<div>
					<h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Recent Activity</h2>
					<p className="text-xs text-zinc-500 dark:text-zinc-500 mt-0.5">
						Last 10 audit entries, auto-refreshes every 15s
					</p>
				</div>
				{lastUpdated && (
					<span className="text-[10px] text-zinc-400 dark:text-zinc-600 tabular-nums">
						Updated{" "}
						{lastUpdated.toLocaleTimeString("en-US", {
							hour: "2-digit",
							minute: "2-digit",
							second: "2-digit",
						})}
					</span>
				)}
			</div>

			{isLoading ? (
				<div className="divide-y divide-zinc-800">
					{Array.from({ length: 5 }).map((_, i) => (
						// biome-ignore lint/suspicious/noArrayIndexKey: static skeleton loader, items never reorder
						<div key={i} className="px-5 py-3.5 flex items-center gap-4 animate-pulse">
							<div className="h-3 w-28 bg-zinc-200 dark:bg-zinc-800 rounded flex-shrink-0" />
							<div className="h-3 w-20 bg-zinc-200 dark:bg-zinc-800 rounded flex-shrink-0" />
							<div className="h-3 w-24 bg-zinc-200 dark:bg-zinc-800 rounded flex-shrink-0" />
							<div className="h-3 flex-1 bg-zinc-200 dark:bg-zinc-800 rounded" />
							<div className="h-5 w-16 bg-zinc-200 dark:bg-zinc-200 dark:bg-zinc-800 rounded-full flex-shrink-0" />
						</div>
					))}
				</div>
			) : entries.length === 0 ? (
				<div className="px-5 py-10 text-center">
					<CalendarClock className="w-8 h-8 text-zinc-700 dark:text-zinc-300 dark:text-zinc-700 mx-auto mb-3" />
					<p className="text-sm text-zinc-400 dark:text-zinc-500">No audit events yet</p>
				</div>
			) : (
				<div className="divide-y divide-zinc-800">
					{entries.map((entry) => (
						<div
							key={entry.id}
							className="px-5 py-3 flex items-center gap-4 text-xs hover:bg-zinc-50 dark:hover:bg-zinc-100/60 dark:bg-zinc-800/40 transition-colors"
						>
							<span className="text-zinc-500 dark:text-zinc-500 tabular-nums flex-shrink-0 w-36">
								{formatTimestamp(entry.timestamp)}
							</span>
							<span className="text-zinc-800 dark:text-zinc-300 font-medium truncate w-32 flex-shrink-0">
								{entry.agentName}
							</span>
							<span className="text-zinc-600 dark:text-zinc-400 font-mono truncate w-24 flex-shrink-0">
								{entry.action}
							</span>
							<span className="text-zinc-600 dark:text-zinc-500 truncate flex-1 font-mono">
								{entry.resource}
							</span>
							<Badge variant={resultVariant(entry.result)}>{resultLabel(entry.result)}</Badge>
						</div>
					))}
				</div>
			)}
		</div>
	);
}

// ─── Overview Page ────────────────────────────────────────────────────────────

export function OverviewPage({ client, onNavigate }: OverviewPageProps) {
	const { data: statsResult, isLoading: statsLoading } = useQuery({
		queryKey: ["dashboard", "stats"],
		queryFn: () => client.getStats(),
		refetchInterval: 30_000,
	});

	const stats = statsResult?.success ? statsResult.data : null;

	// prefetch audit logs so the feed appears quickly
	useEffect(() => {
		void client.getAuditLogs({ limit: 10 });
	}, [client]);

	return (
		<div>
			<PageHeader
				title="Overview"
				description="System-wide health and recent activity at a glance."
			/>

			{/* Stats Cards */}
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
							title="Total Agents"
							value={stats.totalAgents}
							subtitle={`${stats.activeAgents} active`}
							icon={Bot}
							iconColor="bg-amber-600"
						/>
						<StatCard
							title="Auth Rate"
							value={`${Math.round(stats.authAllowedRate)}%`}
							subtitle="allowed vs denied, last 24h"
							icon={ShieldCheck}
							iconColor="bg-emerald-600"
						/>
						<StatCard
							title="Audit Events"
							value={stats.totalAuditEvents.toLocaleString()}
							subtitle={`${stats.recentAuditEvents} in last 24h`}
							icon={CalendarClock}
							iconColor="bg-violet-600"
						/>
						<StatCard
							title="Delegations"
							value={stats.activeDelegations}
							subtitle="active delegations"
							icon={Users}
							iconColor="bg-sky-600"
						/>
					</>
				)}
			</div>

			{/* Main content: activity + quick actions */}
			<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
				{/* Activity Feed — takes up 2/3 */}
				<div className="lg:col-span-2">
					<ActivityFeed client={client} />
				</div>

				{/* Quick Actions — takes up 1/3 */}
				<div className="flex flex-col gap-4">
					<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden">
						<div className="px-5 py-4 border-b border-zinc-200 dark:border-zinc-800">
							<h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Quick Actions</h2>
						</div>
						<div className="p-4 flex flex-col gap-3">
							<button
								type="button"
								onClick={() => onNavigate("agents")}
								className="group flex items-center justify-between w-full px-4 py-3.5 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-700/80 border border-zinc-300 dark:border-zinc-700 hover:border-zinc-600 rounded-lg transition-all duration-100 text-left"
							>
								<div className="flex items-center gap-3">
									<div className="w-8 h-8 rounded-lg bg-amber-600/20 border border-amber-500/30 flex items-center justify-center flex-shrink-0">
										<Bot className="w-4 h-4 text-amber-400" />
									</div>
									<div>
										<p className="text-sm font-medium text-zinc-900 dark:text-white">
											Create Agent
										</p>
										<p className="text-xs text-zinc-500">Register a new AI agent</p>
									</div>
								</div>
								<ArrowRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400 transition-colors" />
							</button>

							<button
								type="button"
								onClick={() => onNavigate("audit")}
								className="group flex items-center justify-between w-full px-4 py-3.5 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-700/80 border border-zinc-300 dark:border-zinc-700 hover:border-zinc-600 rounded-lg transition-all duration-100 text-left"
							>
								<div className="flex items-center gap-3">
									<div className="w-8 h-8 rounded-lg bg-violet-600/20 border border-violet-500/30 flex items-center justify-center flex-shrink-0">
										<CalendarClock className="w-4 h-4 text-violet-400" />
									</div>
									<div>
										<p className="text-sm font-medium text-zinc-900 dark:text-white">
											View Audit Log
										</p>
										<p className="text-xs text-zinc-500">Full immutable event trail</p>
									</div>
								</div>
								<ArrowRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400 transition-colors" />
							</button>
						</div>
					</div>

					{/* Auth rate breakdown */}
					{stats && (
						<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5">
							<h3 className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider mb-4">
								Authorization Breakdown
							</h3>
							<div className="space-y-3">
								<div>
									<div className="flex items-center justify-between mb-1.5">
										<span className="text-xs text-zinc-400">Allowed</span>
										<span className="text-xs font-mono text-emerald-400">
											{Math.round(stats.authAllowedRate)}%
										</span>
									</div>
									<div className="h-1.5 bg-zinc-200 dark:bg-zinc-200 dark:bg-zinc-800 rounded-full overflow-hidden">
										<div
											className="h-full bg-emerald-500 rounded-full transition-all duration-500"
											style={{ width: `${Math.min(100, stats.authAllowedRate)}%` }}
										/>
									</div>
								</div>
								<div>
									<div className="flex items-center justify-between mb-1.5">
										<span className="text-xs text-zinc-400">Denied</span>
										<span className="text-xs font-mono text-red-400">
											{Math.round(100 - stats.authAllowedRate)}%
										</span>
									</div>
									<div className="h-1.5 bg-zinc-200 dark:bg-zinc-200 dark:bg-zinc-800 rounded-full overflow-hidden">
										<div
											className="h-full bg-red-500 rounded-full transition-all duration-500"
											style={{ width: `${Math.min(100, 100 - stats.authAllowedRate)}%` }}
										/>
									</div>
								</div>
							</div>
						</div>
					)}
				</div>
			</div>
		</div>
	);
}
