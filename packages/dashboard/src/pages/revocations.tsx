import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { useState } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type { CreateRevocationInput, DelegationImpact, RevocationKind } from "../api/types.js";
import { Button } from "../components/button.js";
import { FormGroup, Input, Label, Select } from "../components/input.js";
import { PageHeader } from "../components/layout.js";
import { Modal } from "../components/modal.js";
import {
	BusStats,
	DenylistTable,
	describeKind,
	ImpactTable,
	REVOCATION_KINDS,
} from "../components/revocation-tables.js";
import { useToast } from "../components/toast.js";

const POLL_MS = 10_000;

/** The revocation routes ship with the admin API; a 404 means this core does not have them. */
export function revocationsUnavailable(error: { code: string }): boolean {
	return error.code === "HTTP_404";
}

/** Trimmed input for the manual revoke form, or the message to show. */
export function buildRevocationInput(
	kind: RevocationKind,
	id: string,
	reason: string,
): CreateRevocationInput | string {
	const trimmed = id.trim();
	if (!trimmed) return "An id is required";
	const why = reason.trim();
	return why ? { kind, id: trimmed, reason: why } : { kind, id: trimmed };
}

export function RevocationsPage({ client }: { client: TheAuthApiClient }) {
	const queryClient = useQueryClient();
	const { toast } = useToast();
	const [pending, setPending] = useState<CreateRevocationInput | null>(null);
	const [pendingLink, setPendingLink] = useState<DelegationImpact | null>(null);
	const [kind, setKind] = useState<RevocationKind>("agent");
	const [id, setId] = useState("");
	const [reason, setReason] = useState("");
	const [formError, setFormError] = useState<string | null>(null);

	const snapshot = useQuery({
		queryKey: ["revocations"],
		queryFn: () => client.getRevocations(),
		refetchInterval: POLL_MS,
	});
	const impact = useQuery({
		queryKey: ["revocations", "impact"],
		queryFn: () => client.getDelegationImpact(),
		refetchInterval: POLL_MS,
	});

	const revoke = useMutation({
		mutationFn: (input: CreateRevocationInput) => client.createRevocation(input),
		onSuccess: (result) => {
			setPending(null);
			setPendingLink(null);
			if (result.success) {
				toast("success", `Revoked ${result.data.revoked.length} id(s)`);
				setId("");
				setReason("");
			} else {
				toast("error", result.error.message);
			}
			void queryClient.invalidateQueries({ queryKey: ["revocations"] });
		},
		onError: () => toast("error", "Revoke failed"),
	});

	const failed = snapshot.data !== undefined && !snapshot.data.success ? snapshot.data : null;
	const rows = snapshot.data?.success ? snapshot.data.data.rows : [];
	const stats = snapshot.data?.success ? snapshot.data.data.stats : null;
	const links = impact.data?.success ? impact.data.data : [];

	function ask(event: React.FormEvent) {
		event.preventDefault();
		const input = buildRevocationInput(kind, id, reason);
		if (typeof input === "string") {
			setFormError(input);
			return;
		}
		setFormError(null);
		setPending(input);
	}

	return (
		<div>
			<PageHeader
				title="Revocations"
				description="The live MCP denylist, the revocation bus counters, and the delegation links you can cut."
				actions={
					<Button
						variant="secondary"
						size="sm"
						onClick={() => void snapshot.refetch()}
						loading={snapshot.isFetching}
					>
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
					{revocationsUnavailable(failed.error)
						? "The revocation routes are not available. Enable adminApi on a core that includes them."
						: `Could not load revocations: ${failed.error.message}`}
				</div>
			)}

			<BusStats stats={stats} />

			<h2 className="text-sm font-semibold text-zinc-900 dark:text-white mb-2">Delegation links</h2>
			<p className="text-xs text-zinc-500 mb-3">
				MCP tokens are stateless, so each link lists the rule that decides which tokens die: any
				token bound to one of the listed links stops validating. Every revoke is audited.
			</p>
			<div className="mb-8">
				<ImpactTable links={links} onRevoke={setPendingLink} />
			</div>

			<h2 className="text-sm font-semibold text-zinc-900 dark:text-white mb-2">Revoke by id</h2>
			<form onSubmit={ask} className="max-w-xl space-y-3 mb-8" aria-label="Revoke by id">
				<FormGroup>
					<Label htmlFor="revoke-kind">Kind</Label>
					<Select
						id="revoke-kind"
						value={kind}
						onChange={(e) => setKind(e.target.value as RevocationKind)}
					>
						{REVOCATION_KINDS.filter((k) => k !== "dlg").map((k) => (
							<option key={k} value={k}>
								{k}: {describeKind(k)}
							</option>
						))}
					</Select>
				</FormGroup>
				<FormGroup>
					<Label htmlFor="revoke-id" required>
						Id
					</Label>
					<Input id="revoke-id" value={id} onChange={(e) => setId(e.target.value)} />
				</FormGroup>
				<FormGroup>
					<Label htmlFor="revoke-reason">Reason</Label>
					<Input id="revoke-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
				</FormGroup>
				{formError && (
					<p role="alert" className="text-xs text-red-400">
						{formError}
					</p>
				)}
				<Button type="submit" variant="danger">
					Revoke
				</Button>
			</form>

			<h2 className="text-sm font-semibold text-zinc-900 dark:text-white mb-2">Denylist</h2>
			<DenylistTable rows={rows} />

			<Modal
				open={pending !== null || pendingLink !== null}
				onClose={() => {
					setPending(null);
					setPendingLink(null);
				}}
				title="Confirm revoke"
				footer={
					<Button
						variant="danger"
						loading={revoke.isPending}
						onClick={() => {
							if (pendingLink) revoke.mutate({ kind: "dlg", id: pendingLink.id });
							else if (pending) revoke.mutate(pending);
						}}
					>
						Revoke
					</Button>
				}
			>
				<p className="text-sm text-zinc-700 dark:text-zinc-300">
					{pendingLink
						? `Revoke delegation ${pendingLink.id}? This also denies ${pendingLink.cascade.length - 1} downstream link(s) and every token bound to them.`
						: pending
							? `Revoke ${pending.kind} ${pending.id}? It denies ${describeKind(pending.kind)}.`
							: ""}
				</p>
			</Modal>
		</div>
	);
}
