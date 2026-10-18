import { Ban } from "lucide-react";
import type {
	DelegationImpact,
	RevocationBusStats,
	RevocationKind,
	RevocationRow,
} from "../api/types.js";
import { Badge } from "./badge.js";
import { Button } from "./button.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "./table.js";

export const REVOCATION_KINDS: readonly RevocationKind[] = ["jti", "dlg", "agent", "sub", "client"];

/** What a row of this kind denies, in plain words. */
export function describeKind(kind: RevocationKind): string {
	switch (kind) {
		case "jti":
			return "one token";
		case "dlg":
			return "tokens bound to a delegation link";
		case "agent":
			return "tokens acting as an agent";
		case "sub":
			return "tokens of a user minted before the revoke";
		case "client":
			return "tokens of a client minted before the revoke";
	}
}

const STAT_LABELS: Array<[keyof RevocationBusStats, string]> = [
	["published", "Published"],
	["rowsPushed", "Rows pushed"],
	["retries", "Retries"],
	["pushFailures", "Push failures"],
	["attemptFailures", "Failed attempts"],
	["pruned", "Pruned"],
];

/** Bus counters. A non zero push failure count is the one an operator alerts on, so it is flagged. */
export function BusStats({ stats }: { stats: RevocationBusStats | null }) {
	if (!stats) {
		return (
			<p data-testid="bus-stats-missing" className="text-xs text-zinc-500 mb-4">
				This instance has no revocation bus, so no counters are available.
			</p>
		);
	}
	return (
		<dl data-testid="bus-stats" className="grid grid-cols-2 sm:grid-cols-6 gap-3 mb-6">
			{STAT_LABELS.map(([key, label]) => (
				<div key={key} className="rounded-lg border border-zinc-200 dark:border-zinc-800 px-3 py-2">
					<dt className="text-[11px] uppercase tracking-wide text-zinc-500">{label}</dt>
					<dd
						className={`text-lg font-semibold ${
							key === "pushFailures" && stats[key] > 0
								? "text-red-500"
								: "text-zinc-900 dark:text-white"
						}`}
					>
						{stats[key]}
					</dd>
				</div>
			))}
		</dl>
	);
}

export function DenylistTable({ rows }: { rows: RevocationRow[] }) {
	return (
		<Table>
			<TableHead>
				<Th>Kind</Th>
				<Th>Id</Th>
				<Th>Reason</Th>
				<Th>Revoked</Th>
				<Th>Prunable after</Th>
			</TableHead>
			<TableBody>
				{rows.length === 0 ? (
					<tr>
						<td colSpan={5}>
							<EmptyState
								icon={<Ban className="w-6 h-6" />}
								title="No denylist rows"
								description="Revoked delegations, agents, users and tokens appear here until they expire."
							/>
						</td>
					</tr>
				) : (
					rows.map((row) => (
						<Tr key={`${row.kind}:${row.id}`}>
							<Td>
								<Badge variant="gray">{row.kind}</Badge>
							</Td>
							<Td>
								<code className="text-xs font-mono text-zinc-700 dark:text-zinc-300 break-all">
									{row.id}
								</code>
							</Td>
							<Td>
								<span className="text-xs text-zinc-500">{row.reason}</span>
							</Td>
							<Td>
								<span className="text-xs text-zinc-500">{row.revokedAt}</span>
							</Td>
							<Td>
								<span className="text-xs text-zinc-500">{row.expiresAt}</span>
							</Td>
						</Tr>
					))
				)}
			</TableBody>
		</Table>
	);
}

interface ImpactTableProps {
	links: DelegationImpact[];
	onRevoke: (link: DelegationImpact) => void;
}

/** Live delegation links with the cascade a revoke would deny, and the revoke action. */
export function ImpactTable({ links, onRevoke }: ImpactTableProps) {
	return (
		<Table>
			<TableHead>
				<Th>Link</Th>
				<Th>From</Th>
				<Th>To</Th>
				<Th>Would deny</Th>
				<Th>Action</Th>
			</TableHead>
			<TableBody>
				{links.length === 0 ? (
					<tr>
						<td colSpan={5}>
							<EmptyState icon={<Ban className="w-6 h-6" />} title="No live delegation links" />
						</td>
					</tr>
				) : (
					links.map((link) => (
						<Tr key={link.id}>
							<Td>
								<code className="text-xs font-mono">{link.id}</code>
							</Td>
							<Td>
								<code className="text-xs font-mono text-zinc-500">{link.fromAgentId}</code>
							</Td>
							<Td>
								<code className="text-xs font-mono text-zinc-500">{link.toAgentId}</code>
							</Td>
							<Td>
								<span className="text-xs text-zinc-700 dark:text-zinc-300">
									{link.cascade.length} {link.cascade.length === 1 ? "link" : "links"}, tokens bound
									to {link.cascade.join(", ")}
								</span>
							</Td>
							<Td>
								{link.denied ? (
									<Badge variant="red">denied</Badge>
								) : (
									<Button
										size="sm"
										variant="danger"
										onClick={() => onRevoke(link)}
										aria-label={`Revoke delegation ${link.id}`}
									>
										Revoke
									</Button>
								)}
							</Td>
						</Tr>
					))
				)}
			</TableBody>
		</Table>
	);
}
