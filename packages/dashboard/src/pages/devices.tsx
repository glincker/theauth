import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RefreshCw } from "lucide-react";
import { useState } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type { DeviceRow, DeviceStatus, EnrollmentToken } from "../api/device-types.js";
import { Button } from "../components/button.js";
import { DeviceActions } from "../components/device-actions.js";
import { DeviceDetailPanel, DeviceTable, FleetStats } from "../components/device-tables.js";
import { EnrollmentTokenTable } from "../components/enrollment-token-table.js";
import { FormGroup, Input, Label, Select } from "../components/input.js";
import { PageHeader } from "../components/layout.js";
import { Modal } from "../components/modal.js";
import { useToast } from "../components/toast.js";
import type { EnrollFormValues } from "./devices-format.js";
import { buildEnrollmentInput } from "./devices-format.js";

const POLL_MS = 15_000;

const EMPTY_FORM: EnrollFormValues = {
	ownerId: "",
	kind: "claim",
	maxUses: "",
	ttlMinutes: "",
	groups: "",
	deviceKind: "",
};

type PendingAction = { device: DeviceRow; action: "suspend" | "revoke" };

/** A 404 from the device routes means `devices` is not configured on this core. */
export function devicesUnavailable(error: { code: string }): boolean {
	return error.code === "HTTP_404";
}

export function DevicesPage({ client }: { client: TheAuthApiClient }) {
	const queryClient = useQueryClient();
	const { toast } = useToast();
	const [status, setStatus] = useState<DeviceStatus | "">("");
	const [pending, setPending] = useState<PendingAction | null>(null);
	const [selected, setSelected] = useState<DeviceRow | null>(null);
	const [enrollOpen, setEnrollOpen] = useState(false);
	const [form, setForm] = useState<EnrollFormValues>(EMPTY_FORM);
	const [formError, setFormError] = useState<string | null>(null);
	const [issued, setIssued] = useState<EnrollmentToken | null>(null);

	const devices = useQuery({
		queryKey: ["devices", status],
		queryFn: () => client.getDevices(status ? { status } : undefined),
		refetchInterval: POLL_MS,
	});
	const stats = useQuery({
		queryKey: ["devices", "stats"],
		queryFn: () => client.getDeviceStats(),
		refetchInterval: POLL_MS,
	});
	const detail = useQuery({
		queryKey: ["devices", "detail", selected?.id],
		queryFn: () => client.getDevice(selected?.id ?? ""),
		enabled: selected !== null,
	});

	const tokens = useQuery({
		queryKey: ["devices", "enrollment-tokens"],
		queryFn: () => client.listEnrollmentTokens(),
		refetchInterval: POLL_MS,
	});
	const revokeToken = useMutation({
		mutationFn: (id: string) => client.revokeEnrollmentToken(id),
		onSuccess: (result) => {
			if (result.success) toast("success", "Enrollment token revoked");
			else toast("error", result.error.message);
			refresh();
		},
		onError: () => toast("error", "Request failed"),
	});

	function refresh() {
		void queryClient.invalidateQueries({ queryKey: ["devices"] });
	}

	const change = useMutation({
		mutationFn: async (job: { device: DeviceRow; action: "suspend" | "resume" | "revoke" }) => {
			const { device, action } = job;
			if (action === "suspend") return client.suspendDevice(device.id);
			if (action === "resume") return client.resumeDevice(device.id);
			return client.revokeDevice(device.id);
		},
		onSuccess: (result, job) => {
			setPending(null);
			if (result.success) toast("success", `${job.device.name}: ${job.action} done`);
			else toast("error", result.error.message);
			refresh();
		},
		onError: () => toast("error", "Request failed"),
	});

	const enroll = useMutation({
		mutationFn: (input: Parameters<TheAuthApiClient["createEnrollmentToken"]>[0]) =>
			client.createEnrollmentToken(input),
		onSuccess: (result) => {
			if (result.success) {
				setIssued(result.data);
				setForm(EMPTY_FORM);
			} else {
				setFormError(result.error.message);
			}
		},
		onError: () => setFormError("Request failed"),
	});

	const failed = devices.data !== undefined && !devices.data.success ? devices.data : null;
	const rows = devices.data?.success ? devices.data.data : [];

	function submitEnroll(event: React.FormEvent) {
		event.preventDefault();
		const input = buildEnrollmentInput(form);
		if (typeof input === "string") {
			setFormError(input);
			return;
		}
		setFormError(null);
		enroll.mutate(input);
	}

	function closeEnroll() {
		setEnrollOpen(false);
		setIssued(null);
		setFormError(null);
		refresh();
	}

	return (
		<div>
			<PageHeader
				title="Devices"
				description="Fleet health, device state, and enrollment tokens for IoT and robots."
				actions={
					<>
						<Button size="sm" variant="primary" onClick={() => setEnrollOpen(true)}>
							<Plus className="w-3.5 h-3.5" aria-hidden="true" />
							Enroll token
						</Button>
						<Button size="sm" onClick={refresh} loading={devices.isFetching}>
							<RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
							Refresh
						</Button>
					</>
				}
			/>

			{failed && (
				<div
					role="alert"
					className="mb-4 rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-400"
				>
					{devicesUnavailable(failed.error)
						? "Devices are not configured. Set `devices` in createTheAuth."
						: `Could not load devices: ${failed.error.message}`}
				</div>
			)}

			<FleetStats stats={stats.data?.success ? stats.data.data : null} />

			<div className="mb-4 max-w-[200px]">
				<Select
					value={status}
					onChange={(e) => setStatus(e.target.value as DeviceStatus | "")}
					aria-label="Filter by status"
				>
					<option value="">All statuses</option>
					<option value="active">Active</option>
					<option value="suspended">Suspended</option>
					<option value="revoked">Revoked</option>
				</Select>
			</div>

			<DeviceTable
				devices={rows}
				now={Date.now()}
				busyId={change.isPending ? change.variables?.device.id : null}
				onSelect={setSelected}
				onSuspend={(device) => setPending({ device, action: "suspend" })}
				onResume={(device) => change.mutate({ device, action: "resume" })}
				onRevoke={(device) => setPending({ device, action: "revoke" })}
			/>

			<h2 className="mt-8 mb-3 text-sm font-semibold text-zinc-900 dark:text-white">
				Enrollment tokens
			</h2>
			<EnrollmentTokenTable
				tokens={tokens.data?.success ? tokens.data.data : []}
				busyId={revokeToken.isPending ? revokeToken.variables : null}
				onRevoke={(token) => revokeToken.mutate(token.id)}
			/>

			<Modal
				open={pending !== null}
				onClose={() => setPending(null)}
				title={pending?.action === "revoke" ? "Revoke device" : "Suspend device"}
				footer={
					<Button
						variant="danger"
						loading={change.isPending}
						onClick={() => pending && change.mutate(pending)}
					>
						{pending?.action === "revoke" ? "Revoke" : "Suspend"}
					</Button>
				}
			>
				<p className="text-sm text-zinc-700 dark:text-zinc-300">
					{pending?.action === "revoke"
						? `Revoke ${pending.device.name}? This is permanent and cuts every delegation it holds.`
						: pending
							? `Suspend ${pending.device.name}? It is refused until you resume it.`
							: ""}
				</p>
			</Modal>

			<Modal
				open={selected !== null}
				onClose={() => setSelected(null)}
				title={selected?.name ?? "Device"}
			>
				{detail.data?.success ? (
					<>
						<DeviceDetailPanel device={detail.data.data} />
						<DeviceActions key={detail.data.data.id} client={client} device={detail.data.data} />
					</>
				) : detail.data ? (
					<p role="alert" className="text-xs text-red-400">
						{detail.data.error.message}
					</p>
				) : (
					<p className="text-xs text-zinc-500">Loading</p>
				)}
			</Modal>

			<Modal open={enrollOpen} onClose={closeEnroll} title="Create enrollment token">
				{issued ? (
					<div data-testid="issued-token" className="space-y-3">
						<p className="text-sm text-zinc-700 dark:text-zinc-300">
							Copy this {issued.kind === "claim" ? "claim code" : "token"} now. It is shown once and
							cannot be read back.
						</p>
						<code className="block break-all rounded-lg bg-zinc-100 dark:bg-zinc-800 px-3 py-2 text-xs font-mono">
							{issued.token}
						</code>
						<p className="text-xs text-zinc-500">
							Up to {issued.maxUses} use(s), expires {new Date(issued.expiresAt).toLocaleString()}.
						</p>
						<Button variant="primary" onClick={closeEnroll}>
							Done
						</Button>
					</div>
				) : (
					<form onSubmit={submitEnroll} className="space-y-3" aria-label="Create enrollment token">
						<FormGroup>
							<Label htmlFor="enroll-owner" required>
								Owner id
							</Label>
							<Input
								id="enroll-owner"
								value={form.ownerId}
								onChange={(e) => setForm({ ...form, ownerId: e.target.value })}
							/>
						</FormGroup>
						<FormGroup>
							<Label htmlFor="enroll-kind">Kind</Label>
							<Select
								id="enroll-kind"
								value={form.kind}
								onChange={(e) => setForm({ ...form, kind: e.target.value as "claim" | "bulk" })}
							>
								<option value="claim">Claim code (one device)</option>
								<option value="bulk">Bulk token (many devices)</option>
							</Select>
						</FormGroup>
						<FormGroup>
							<Label htmlFor="enroll-uses">Max uses</Label>
							<Input
								id="enroll-uses"
								inputMode="numeric"
								value={form.maxUses}
								onChange={(e) => setForm({ ...form, maxUses: e.target.value })}
							/>
						</FormGroup>
						<FormGroup>
							<Label htmlFor="enroll-ttl">Lifetime in minutes</Label>
							<Input
								id="enroll-ttl"
								inputMode="numeric"
								value={form.ttlMinutes}
								onChange={(e) => setForm({ ...form, ttlMinutes: e.target.value })}
							/>
						</FormGroup>
						<FormGroup>
							<Label htmlFor="enroll-groups">Groups (comma separated)</Label>
							<Input
								id="enroll-groups"
								value={form.groups}
								onChange={(e) => setForm({ ...form, groups: e.target.value })}
							/>
						</FormGroup>
						<FormGroup>
							<Label htmlFor="enroll-device-kind">Device kind</Label>
							<Input
								id="enroll-device-kind"
								value={form.deviceKind}
								onChange={(e) => setForm({ ...form, deviceKind: e.target.value })}
							/>
						</FormGroup>
						{formError && (
							<p role="alert" className="text-xs text-red-400">
								{formError}
							</p>
						)}
						<Button type="submit" variant="primary" loading={enroll.isPending}>
							Create token
						</Button>
					</form>
				)}
			</Modal>
		</div>
	);
}
