import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, Clock, Database, Save, Zap } from "lucide-react";
import { useState } from "react";
import type { KavachApiClient } from "../api/client.js";
import type { KavachSettings } from "../api/types.js";
import { Button } from "../components/button.js";
import { FormGroup, Input, Label } from "../components/input.js";
import { PageHeader } from "../components/layout.js";

// ─── Section Card ─────────────────────────────────────────────────────────────

import type { ReactNode } from "react";

interface SectionCardProps {
	icon: ReactNode;
	title: string;
	description: string;
	children: ReactNode;
}

function SectionCard({ icon, title, description, children }: SectionCardProps) {
	return (
		<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-5">
			<div className="flex items-start gap-3 mb-5">
				<div className="w-8 h-8 rounded-lg bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center flex-shrink-0 text-zinc-400">
					{icon}
				</div>
				<div>
					<h2 className="text-sm font-semibold text-zinc-900 dark:text-white">{title}</h2>
					<p className="text-xs text-zinc-500 mt-0.5">{description}</p>
				</div>
			</div>
			{children}
		</div>
	);
}

// ─── Read-only Field ──────────────────────────────────────────────────────────

interface ReadOnlyFieldProps {
	label: string;
	value: string;
}

function ReadOnlyField({ label, value }: ReadOnlyFieldProps) {
	return (
		<div>
			<p className="text-xs font-medium text-zinc-500 mb-1">{label}</p>
			<p className="text-sm font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg px-3 py-2">
				{value}
			</p>
		</div>
	);
}

// ─── Settings Form ────────────────────────────────────────────────────────────

interface SettingsFormProps {
	settings: KavachSettings;
	onSave: (updates: Partial<Omit<KavachSettings, "database">>) => void;
	loading: boolean;
}

function SettingsForm({ settings, onSave, loading }: SettingsFormProps) {
	const [tokenExpiry, setTokenExpiry] = useState(String(settings.tokenExpirySeconds));
	const [rateLimitRequests, setRateLimitRequests] = useState(
		String(settings.rateLimitRequestsPerMinute),
	);
	const [rateLimitWindow, setRateLimitWindow] = useState(String(settings.rateLimitWindowSeconds));
	const [auditRetention, setAuditRetention] = useState(String(settings.auditRetentionDays));
	const [maxAgents, setMaxAgents] = useState(String(settings.maxAgentsPerTenant));

	function handleSave() {
		onSave({
			tokenExpirySeconds: Number(tokenExpiry),
			rateLimitRequestsPerMinute: Number(rateLimitRequests),
			rateLimitWindowSeconds: Number(rateLimitWindow),
			auditRetentionDays: Number(auditRetention),
			maxAgentsPerTenant: Number(maxAgents),
		});
	}

	return (
		<div className="space-y-5">
			{/* Database Info */}
			<SectionCard
				icon={<Database className="w-4 h-4" />}
				title="Database"
				description="Connection information. Managed via environment variables."
			>
				<div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
					<ReadOnlyField label="Adapter" value={settings.database.adapter} />
					<ReadOnlyField label="Version" value={settings.database.version} />
					<ReadOnlyField
						label="Connection"
						value={settings.database.url.replace(/:[^:@]+@/, ":***@")}
					/>
				</div>
			</SectionCard>

			{/* Token Expiry */}
			<SectionCard
				icon={<Clock className="w-4 h-4" />}
				title="Token Expiry"
				description="Default lifetime for agent tokens before they must be rotated."
			>
				<div className="max-w-xs">
					<FormGroup>
						<Label htmlFor="token-expiry">Expiry (seconds)</Label>
						<div className="flex items-center gap-3">
							<Input
								id="token-expiry"
								type="number"
								min={60}
								max={31_536_000}
								value={tokenExpiry}
								onChange={(e) => setTokenExpiry(e.target.value)}
							/>
							<span className="text-xs text-zinc-500 whitespace-nowrap flex-shrink-0">
								{Math.round(Number(tokenExpiry) / 3600)}h
							</span>
						</div>
					</FormGroup>
					<p className="text-[11px] text-zinc-500 mt-2">
						Recommended: 3600 (1h) for automated agents, 86400 (24h) for service accounts.
					</p>
				</div>
			</SectionCard>

			{/* Rate Limits */}
			<SectionCard
				icon={<Zap className="w-4 h-4" />}
				title="Rate Limits"
				description="Default rate limiting applied to all agents unless overridden by permission constraints."
			>
				<div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-md">
					<FormGroup>
						<Label htmlFor="rate-limit-requests">Requests per window</Label>
						<Input
							id="rate-limit-requests"
							type="number"
							min={1}
							value={rateLimitRequests}
							onChange={(e) => setRateLimitRequests(e.target.value)}
						/>
					</FormGroup>
					<FormGroup>
						<Label htmlFor="rate-limit-window">Window (seconds)</Label>
						<Input
							id="rate-limit-window"
							type="number"
							min={1}
							value={rateLimitWindow}
							onChange={(e) => setRateLimitWindow(e.target.value)}
						/>
					</FormGroup>
				</div>
				<p className="text-[11px] text-zinc-500 mt-2">
					Current: {rateLimitRequests} requests per {rateLimitWindow}s window.
				</p>
			</SectionCard>

			{/* Audit Retention */}
			<SectionCard
				icon={<Archive className="w-4 h-4" />}
				title="Audit Retention"
				description="How long audit log entries are retained before automatic deletion."
			>
				<div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-md">
					<FormGroup>
						<Label htmlFor="audit-retention">Retention (days)</Label>
						<Input
							id="audit-retention"
							type="number"
							min={1}
							max={3650}
							value={auditRetention}
							onChange={(e) => setAuditRetention(e.target.value)}
						/>
					</FormGroup>
					<FormGroup>
						<Label htmlFor="max-agents">Max agents per tenant</Label>
						<Input
							id="max-agents"
							type="number"
							min={1}
							value={maxAgents}
							onChange={(e) => setMaxAgents(e.target.value)}
						/>
					</FormGroup>
				</div>
				<p className="text-[11px] text-zinc-500 mt-2">
					EU AI Act Article 12 requires minimum 90 days. SOC 2 recommends 365+ days.
				</p>
			</SectionCard>

			{/* Save */}
			<div className="flex justify-end pt-2">
				<Button variant="primary" onClick={handleSave} loading={loading}>
					<Save className="w-3.5 h-3.5" />
					Save Settings
				</Button>
			</div>
		</div>
	);
}

// ─── Settings Page ────────────────────────────────────────────────────────────

interface SettingsPageProps {
	client: KavachApiClient;
}

export function SettingsPage({ client }: SettingsPageProps) {
	const queryClient = useQueryClient();

	const { data: settingsResult, isLoading } = useQuery({
		queryKey: ["settings"],
		queryFn: () => client.getSettings(),
	});

	const updateMutation = useMutation({
		mutationFn: (updates: Partial<Omit<KavachSettings, "database">>) =>
			client.updateSettings(updates),
		onSuccess: (result) => {
			if (result.success) {
				void queryClient.invalidateQueries({ queryKey: ["settings"] });
			}
		},
	});

	return (
		<div>
			<PageHeader title="Settings" description="System configuration and operational parameters." />

			{isLoading ? (
				<div className="flex items-center justify-center py-16">
					<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
				</div>
			) : settingsResult?.success ? (
				<SettingsForm
					settings={settingsResult.data}
					onSave={(updates) => updateMutation.mutate(updates)}
					loading={updateMutation.isPending}
				/>
			) : (
				<div className="bg-red-950/30 border border-red-800/50 rounded-xl p-5">
					<p className="text-sm text-red-400">
						Failed to load settings. Check that your TheAuth API is reachable.
					</p>
					{settingsResult && !settingsResult.success && (
						<p className="text-xs text-red-500 mt-1 font-mono">
							{settingsResult.error.code}: {settingsResult.error.message}
						</p>
					)}
				</div>
			)}
		</div>
	);
}
