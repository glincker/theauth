import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Network, XCircle } from "lucide-react";
import type { KavachApiClient } from "../api/client.js";
import type { DelegationChain, DelegationStatus } from "../api/types.js";
import { Badge } from "../components/badge.js";
import { Button } from "../components/button.js";
import { PageHeader } from "../components/layout.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatRelativeTime(iso: string): string {
	const now = Date.now();
	const target = new Date(iso).getTime();
	const diffMs = target - now;
	const diffSec = Math.round(diffMs / 1000);
	const absSec = Math.abs(diffSec);

	const units: Array<[number, string]> = [
		[86400, "d"],
		[3600, "h"],
		[60, "m"],
	];

	for (const [secs, label] of units) {
		if (absSec >= secs) {
			const val = Math.floor(absSec / secs);
			return diffSec >= 0 ? `in ${val}${label}` : `${val}${label} ago`;
		}
	}

	return diffSec >= 0 ? "in <1m" : "just now";
}

function statusVariant(status: DelegationStatus): "green" | "yellow" | "red" {
	switch (status) {
		case "active":
			return "green";
		case "expired":
			return "yellow";
		case "revoked":
			return "red";
	}
}

// ─── Permissions Cell ─────────────────────────────────────────────────────────

interface PermissionsCellProps {
	permissions: DelegationChain["permissions"];
}

function PermissionsCell({ permissions }: PermissionsCellProps) {
	const count = permissions.length;

	if (count === 0) {
		return <span className="text-xs text-zinc-600">None</span>;
	}

	const summary = permissions
		.slice(0, 2)
		.map((p) => p.resource)
		.join(", ");

	return (
		<div title={permissions.map((p) => `${p.resource}: ${p.actions.join(", ")}`).join("\n")}>
			<span className="text-xs text-zinc-300">
				{count} {count === 1 ? "permission" : "permissions"}
			</span>
			<p className="text-[11px] text-zinc-600 mt-0.5 max-w-[160px] truncate">
				{summary}
				{count > 2 ? ` +${count - 2} more` : ""}
			</p>
		</div>
	);
}

// ─── Delegations Page ─────────────────────────────────────────────────────────

interface DelegationsPageProps {
	client: KavachApiClient;
}

export function DelegationsPage({ client }: DelegationsPageProps) {
	const queryClient = useQueryClient();

	const { data: delegationsResult, isLoading } = useQuery({
		queryKey: ["delegations"],
		queryFn: () => client.getDelegations(),
	});

	const revokeMutation = useMutation({
		mutationFn: (id: string) => client.revokeDelegation(id),
		onSuccess: () => {
			void queryClient.invalidateQueries({ queryKey: ["delegations"] });
		},
	});

	const delegations = delegationsResult?.success ? delegationsResult.data : [];

	return (
		<div>
			<PageHeader
				title="Delegations"
				description="Active delegation chains between agents. Each chain grants a subset of the delegating agent's permissions."
			/>

			{isLoading ? (
				<div className="flex items-center justify-center py-16">
					<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
				</div>
			) : delegations.length === 0 ? (
				<Table>
					<TableHead>
						<Th>ID</Th>
						<Th>Chain</Th>
						<Th>Permissions</Th>
						<Th>Depth</Th>
						<Th>Expires</Th>
						<Th>Status</Th>
						<Th />
					</TableHead>
					<TableBody>
						<tr>
							<td colSpan={7}>
								<EmptyState
									icon={<Network className="w-6 h-6" />}
									title="No delegation chains"
									description="Delegations let one agent grant a subset of its permissions to another. Use the SDK to create delegation chains between agents."
									docsLink="https://theauth.dev/docs/delegation"
								/>
							</td>
						</tr>
					</TableBody>
				</Table>
			) : (
				<Table>
					<TableHead>
						<Th>ID</Th>
						<Th>Chain</Th>
						<Th>Permissions</Th>
						<Th>Depth</Th>
						<Th>Expires</Th>
						<Th>Status</Th>
						<Th />
					</TableHead>
					<TableBody>
						{delegations.map((dlg) => (
							<Tr key={dlg.id}>
								<Td>
									<code className="text-xs font-mono text-zinc-500">{dlg.id}</code>
								</Td>
								<Td>
									<div className="flex items-center gap-2">
										<span className="text-sm text-zinc-200 font-medium max-w-[120px] truncate">
											{dlg.fromAgentName}
										</span>
										<ArrowRight className="w-3.5 h-3.5 text-zinc-600 flex-shrink-0" />
										<span className="text-sm text-zinc-200 font-medium max-w-[120px] truncate">
											{dlg.toAgentName}
										</span>
									</div>
									<div className="flex gap-1 mt-0.5">
										<code className="text-[10px] font-mono text-zinc-600">{dlg.fromAgentId}</code>
										<span className="text-[10px] text-zinc-700">→</span>
										<code className="text-[10px] font-mono text-zinc-600">{dlg.toAgentId}</code>
									</div>
								</Td>
								<Td>
									<PermissionsCell permissions={dlg.permissions} />
								</Td>
								<Td>
									<span className="text-xs font-mono text-zinc-400">
										{dlg.depth}/{dlg.maxDepth}
									</span>
								</Td>
								<Td>
									<span
										className={[
											"text-xs",
											dlg.status === "expired" || new Date(dlg.expiresAt) < new Date()
												? "text-amber-400"
												: "text-zinc-400",
										].join(" ")}
									>
										{formatRelativeTime(dlg.expiresAt)}
									</span>
								</Td>
								<Td>
									<Badge variant={statusVariant(dlg.status)}>{dlg.status}</Badge>
								</Td>
								<Td className="text-right">
									{dlg.status === "active" && (
										<Button
											variant="ghost"
											onClick={() => revokeMutation.mutate(dlg.id)}
											disabled={revokeMutation.isPending && revokeMutation.variables === dlg.id}
										>
											<XCircle className="w-3.5 h-3.5 text-red-400" />
											<span className="text-red-400">Revoke</span>
										</Button>
									)}
								</Td>
							</Tr>
						))}
					</TableBody>
				</Table>
			)}
		</div>
	);
}
