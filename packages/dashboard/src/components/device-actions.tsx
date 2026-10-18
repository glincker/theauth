import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type {
	AddedDeviceCredential,
	DeviceBundle,
	DeviceCredentialInput,
	DeviceDetail,
} from "../api/device-types.js";
import { buildCredentialInput, parseBundleTtl, parseGroups } from "../pages/devices-format.js";
import { Button } from "./button.js";
import { FormGroup, Input, Label, Select, Textarea } from "./input.js";
import { useToast } from "./toast.js";

const CODE = "block break-all rounded-lg bg-zinc-100 dark:bg-zinc-800 px-3 py-2 text-xs font-mono";

interface Props {
	client: TheAuthApiClient;
	device: DeviceDetail;
}

/** Edit groups, add or revoke a credential and issue a policy bundle for one device. */
export function DeviceActions({ client, device }: Props) {
	const queryClient = useQueryClient();
	const { toast } = useToast();
	const locked = device.status === "revoked";
	const [groups, setGroups] = useState(device.groups.join(", "));
	const [kind, setKind] = useState<DeviceCredentialInput["kind"]>("psk");
	const [material, setMaterial] = useState("");
	const [ttl, setTtl] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [added, setAdded] = useState<AddedDeviceCredential | null>(null);
	const [bundle, setBundle] = useState<DeviceBundle | null>(null);

	function refresh() {
		void queryClient.invalidateQueries({ queryKey: ["devices"] });
	}

	function report<T>(
		result: { success: true; data: T } | { success: false; error: { message: string } },
	) {
		if (result.success) {
			setError(null);
			return result.data;
		}
		setError(result.error.message);
		toast("error", result.error.message);
		return null;
	}

	const saveGroups = useMutation({
		mutationFn: () => client.updateDeviceGroups(device.id, parseGroups(groups)),
		onSuccess: (result) => {
			if (report(result)) {
				toast("success", "Groups saved");
				refresh();
			}
		},
		onError: () => setError("Request failed"),
	});

	const addCredential = useMutation({
		mutationFn: (input: DeviceCredentialInput) => client.addDeviceCredential(device.id, input),
		onSuccess: (result) => {
			const data = report(result);
			if (data) {
				setAdded(data);
				setMaterial("");
				refresh();
			}
		},
		onError: () => setError("Request failed"),
	});

	const revokeCredential = useMutation({
		mutationFn: (credentialId: string) => client.revokeDeviceCredential(device.id, credentialId),
		onSuccess: (result) => {
			if (report(result) !== null) {
				toast("success", "Credential revoked");
				refresh();
			}
		},
		onError: () => setError("Request failed"),
	});

	const issueBundle = useMutation({
		mutationFn: (ttlSeconds: number | undefined) => client.issueDeviceBundle(device.id, ttlSeconds),
		onSuccess: (result) => {
			const data = report(result);
			if (data) setBundle(data);
		},
		onError: () => setError("Request failed"),
	});

	function submitCredential(event: React.FormEvent) {
		event.preventDefault();
		const input = buildCredentialInput(kind, material);
		if (typeof input === "string") {
			setError(input);
			return;
		}
		setError(null);
		setAdded(null);
		addCredential.mutate(input);
	}

	function submitBundle(event: React.FormEvent) {
		event.preventDefault();
		const seconds = parseBundleTtl(ttl);
		if (typeof seconds === "string") {
			setError(seconds);
			return;
		}
		setError(null);
		setBundle(null);
		issueBundle.mutate(seconds);
	}

	return (
		<div
			data-testid="device-actions"
			className="mt-4 space-y-5 border-t border-zinc-200 dark:border-zinc-800 pt-4"
		>
			{error && (
				<p role="alert" className="text-xs text-red-400">
					{error}
				</p>
			)}

			<form
				onSubmit={(e) => {
					e.preventDefault();
					saveGroups.mutate();
				}}
				aria-label="Edit groups"
				className="space-y-2"
			>
				<FormGroup>
					<Label htmlFor="device-groups">Groups (comma separated)</Label>
					<Input
						id="device-groups"
						value={groups}
						disabled={locked}
						onChange={(e) => setGroups(e.target.value)}
					/>
				</FormGroup>
				<Button type="submit" size="sm" disabled={locked} loading={saveGroups.isPending}>
					Save groups
				</Button>
			</form>

			{device.credentials.some((c) => c.status === "active") && (
				<ul className="space-y-1" aria-label="Active credentials">
					{device.credentials
						.filter((c) => c.status === "active")
						.map((c) => (
							<li key={c.id} className="flex items-center justify-between gap-2 text-xs">
								<span className="font-mono truncate">
									{c.kind} {c.lookup}
								</span>
								<Button
									size="sm"
									variant="danger"
									disabled={revokeCredential.isPending}
									onClick={() => revokeCredential.mutate(c.id)}
									aria-label={`Revoke credential ${c.lookup}`}
								>
									Revoke
								</Button>
							</li>
						))}
				</ul>
			)}

			<form onSubmit={submitCredential} aria-label="Add credential" className="space-y-2">
				<FormGroup>
					<Label htmlFor="credential-kind">New credential</Label>
					<Select
						id="credential-kind"
						value={kind}
						disabled={locked}
						onChange={(e) => setKind(e.target.value as DeviceCredentialInput["kind"])}
					>
						<option value="psk">Pre shared key (generated)</option>
						<option value="jwk">Public JWK</option>
						<option value="x509">Certificate thumbprint</option>
					</Select>
				</FormGroup>
				{kind === "jwk" && (
					<Textarea
						aria-label="Public JWK"
						rows={4}
						value={material}
						onChange={(e) => setMaterial(e.target.value)}
					/>
				)}
				{kind === "x509" && (
					<Input
						aria-label="x5t#S256 thumbprint"
						value={material}
						onChange={(e) => setMaterial(e.target.value)}
					/>
				)}
				<Button type="submit" size="sm" disabled={locked} loading={addCredential.isPending}>
					Add credential
				</Button>
				{added?.secret && (
					<div data-testid="added-secret" className="space-y-1">
						<p className="text-xs text-zinc-600 dark:text-zinc-400">
							Copy this key now. It is shown once and cannot be read back.
						</p>
						<code className={CODE}>{added.secret}</code>
					</div>
				)}
			</form>

			<form onSubmit={submitBundle} aria-label="Issue bundle" className="space-y-2">
				<FormGroup>
					<Label htmlFor="bundle-ttl">Policy bundle lifetime in seconds (optional)</Label>
					<Input
						id="bundle-ttl"
						inputMode="numeric"
						value={ttl}
						disabled={locked}
						onChange={(e) => setTtl(e.target.value)}
					/>
				</FormGroup>
				<Button type="submit" size="sm" disabled={locked} loading={issueBundle.isPending}>
					Issue bundle
				</Button>
				{bundle && (
					<div data-testid="issued-bundle" className="space-y-1">
						<code className={CODE}>{bundle.token}</code>
					</div>
				)}
			</form>
		</div>
	);
}
