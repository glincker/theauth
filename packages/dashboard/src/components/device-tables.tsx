import { Cpu } from "lucide-react";
import type { DeviceDetail, DeviceFleetStats, DeviceRow } from "../api/device-types.js";
import {
	activeCredentialKinds,
	formatLastSeen,
	spiffeTrustDomain,
	statusTone,
} from "../pages/devices-format.js";
import { Badge } from "./badge.js";
import { Button } from "./button.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "./table.js";

const TILES: Array<{ key: keyof DeviceFleetStats; label: string }> = [
	{ key: "total", label: "Total" },
	{ key: "active", label: "Active" },
	{ key: "suspended", label: "Suspended" },
	{ key: "revoked", label: "Revoked" },
	{ key: "seenLastHour", label: "Seen in 1h" },
	{ key: "seenLastDay", label: "Seen in 24h" },
	{ key: "neverSeen", label: "Never seen" },
];

/** Fleet health counters from GET /devices/stats. */
export function FleetStats({ stats }: { stats: DeviceFleetStats | null }) {
	return (
		<dl
			data-testid="fleet-stats"
			className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 mb-6"
		>
			{TILES.map((tile) => (
				<div
					key={tile.key}
					className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-3 py-2.5"
				>
					<dt className="text-[10px] uppercase tracking-wider text-zinc-500">{tile.label}</dt>
					<dd className="text-lg font-semibold text-zinc-900 dark:text-white">
						{stats ? stats[tile.key] : "-"}
					</dd>
				</div>
			))}
		</dl>
	);
}

interface DeviceTableProps {
	devices: DeviceRow[];
	now: number;
	busyId?: string | null;
	onSelect: (device: DeviceRow) => void;
	onSuspend: (device: DeviceRow) => void;
	onResume: (device: DeviceRow) => void;
	onRevoke: (device: DeviceRow) => void;
}

function Head() {
	return (
		<TableHead>
			<Th>Name</Th>
			<Th>Kind</Th>
			<Th>Status</Th>
			<Th>Groups</Th>
			<Th>Last seen</Th>
			<Th>
				<span className="sr-only">Actions</span>
			</Th>
		</TableHead>
	);
}

export function DeviceTable({
	devices,
	now,
	busyId,
	onSelect,
	onSuspend,
	onResume,
	onRevoke,
}: DeviceTableProps) {
	if (devices.length === 0) {
		return (
			<Table>
				<Head />
				<TableBody>
					<tr>
						<td colSpan={6}>
							<EmptyState
								icon={<Cpu className="w-6 h-6" />}
								title="No devices"
								description="Create an enrollment token and give the claim code to a device, or register one through the API."
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
				{devices.map((device) => (
					<Tr key={device.id}>
						<Td>
							<button
								type="button"
								onClick={() => onSelect(device)}
								className="text-left text-xs font-medium text-zinc-800 dark:text-zinc-200 hover:underline"
							>
								{device.name}
							</button>
							<span className="block text-[10px] font-mono text-zinc-500">{device.id}</span>
						</Td>
						<Td>
							<span className="text-xs">{device.kind ?? "-"}</span>
						</Td>
						<Td>
							<Badge variant={statusTone(device.status)}>{device.status}</Badge>
						</Td>
						<Td>
							<span className="text-xs">
								{device.groups.length > 0 ? device.groups.join(", ") : "-"}
							</span>
						</Td>
						<Td>
							<span className="text-xs font-mono" title={device.lastSeenAt ?? undefined}>
								{formatLastSeen(device.lastSeenAt, now)}
							</span>
						</Td>
						<Td>
							<div className="flex items-center gap-1.5 justify-end">
								{device.status === "active" && (
									<Button
										size="sm"
										disabled={busyId === device.id}
										onClick={() => onSuspend(device)}
										aria-label={`Suspend ${device.name}`}
									>
										Suspend
									</Button>
								)}
								{device.status === "suspended" && (
									<Button
										size="sm"
										disabled={busyId === device.id}
										onClick={() => onResume(device)}
										aria-label={`Resume ${device.name}`}
									>
										Resume
									</Button>
								)}
								{device.status !== "revoked" && (
									<Button
										size="sm"
										variant="danger"
										disabled={busyId === device.id}
										onClick={() => onRevoke(device)}
										aria-label={`Revoke ${device.name}`}
									>
										Revoke
									</Button>
								)}
							</div>
						</Td>
					</Tr>
				))}
			</TableBody>
		</Table>
	);
}

/** One device with its credentials (kind and state only, never key material). */
export function DeviceDetailPanel({ device }: { device: DeviceDetail }) {
	return (
		<div data-testid="device-detail" className="space-y-3 text-xs text-zinc-700 dark:text-zinc-300">
			<p>
				Credential kinds in use:{" "}
				<span className="font-mono">{activeCredentialKinds(device.credentials)}</span>
			</p>
			{device.statusReason && <p>Reason: {device.statusReason}</p>}
			{device.hardwareId && (
				<p>
					Hardware id: <span className="font-mono">{device.hardwareId}</span>
				</p>
			)}
			{device.lastSeenIp && (
				<p>
					Last IP: <span className="font-mono">{device.lastSeenIp}</span>
				</p>
			)}
			<ul className="space-y-1">
				{device.credentials.map((c) => (
					<li key={c.id} className="flex items-center gap-2">
						<Badge variant={c.status === "active" ? "green" : "gray"}>{c.kind}</Badge>
						<span className="font-mono truncate">{c.lookup}</span>
						<span className="text-zinc-500">{c.status}</span>
					</li>
				))}
				{device.credentials.length === 0 && <li className="text-zinc-500">No credentials</li>}
			</ul>
			{device.credentials.some((c) => c.kind === "spiffe") && (
				<div data-testid="device-spiffe" className="space-y-1">
					<p className="font-medium">SPIFFE identities</p>
					<ul className="space-y-1" aria-label="SPIFFE identities">
						{device.credentials
							.filter((c) => c.kind === "spiffe")
							.map((c) => (
								<li key={c.id} className="flex items-center gap-2">
									<span className="font-mono truncate">{c.lookup}</span>
									<span className="text-zinc-500">
										trust domain {spiffeTrustDomain(c.lookup) ?? "unknown"}, {c.status}
									</span>
								</li>
							))}
					</ul>
				</div>
			)}
		</div>
	);
}
