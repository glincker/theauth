import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Server } from "lucide-react";
import { useState } from "react";
import type { TheAuthApiClient } from "../api/client.js";
import type { McpServerInfo, RegisterMcpServerInput } from "../api/types.js";
import { Badge, StatusDot } from "../components/badge.js";
import { Button } from "../components/button.js";
import { FormGroup, Input, Label } from "../components/input.js";
import { PageHeader } from "../components/layout.js";
import { Modal } from "../components/modal.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusVariant(status: McpServerInfo["status"]): "green" | "red" | "gray" {
	switch (status) {
		case "online":
			return "green";
		case "offline":
			return "red";
		case "unknown":
			return "gray";
	}
}

// ─── Register MCP Server Modal ────────────────────────────────────────────────

interface RegisterModalProps {
	open: boolean;
	onClose: () => void;
	onSubmit: (input: RegisterMcpServerInput) => void;
	loading: boolean;
}

function RegisterMcpServerModal({ open, onClose, onSubmit, loading }: RegisterModalProps) {
	const [name, setName] = useState("");
	const [endpoint, setEndpoint] = useState("");
	const [toolsRaw, setToolsRaw] = useState("");
	const [authRequired, setAuthRequired] = useState(false);
	const [rateLimitRpm, setRateLimitRpm] = useState("");
	const [nameError, setNameError] = useState("");
	const [endpointError, setEndpointError] = useState("");

	function handleSubmit() {
		let valid = true;

		if (!name.trim()) {
			setNameError("Name is required");
			valid = false;
		} else {
			setNameError("");
		}

		if (!endpoint.trim()) {
			setEndpointError("Endpoint URL is required");
			valid = false;
		} else {
			setEndpointError("");
		}

		if (!valid) return;

		const tools = toolsRaw
			.split(",")
			.map((t) => t.trim())
			.filter(Boolean);

		const rpm = rateLimitRpm.trim() ? Number(rateLimitRpm.trim()) : undefined;

		onSubmit({
			name: name.trim(),
			endpoint: endpoint.trim(),
			tools,
			authRequired,
			rateLimit: rpm && rpm > 0 ? { rpm } : undefined,
		});
	}

	function handleClose() {
		setName("");
		setEndpoint("");
		setToolsRaw("");
		setAuthRequired(false);
		setRateLimitRpm("");
		setNameError("");
		setEndpointError("");
		onClose();
	}

	return (
		<Modal
			open={open}
			onClose={handleClose}
			title="Register MCP Server"
			footer={
				<>
					<Button variant="ghost" onClick={handleClose}>
						Cancel
					</Button>
					<Button variant="primary" onClick={handleSubmit} loading={loading}>
						Register Server
					</Button>
				</>
			}
		>
			<div className="space-y-4">
				<FormGroup>
					<Label htmlFor="mcp-name" required>
						Name
					</Label>
					<Input
						id="mcp-name"
						placeholder="e.g. filesystem-tools"
						value={name}
						onChange={(e) => setName(e.target.value)}
						error={nameError}
						autoFocus
					/>
				</FormGroup>

				<FormGroup>
					<Label htmlFor="mcp-endpoint" required>
						Endpoint URL
					</Label>
					<Input
						id="mcp-endpoint"
						placeholder="https://mcp.example.com/sse"
						value={endpoint}
						onChange={(e) => setEndpoint(e.target.value)}
						error={endpointError}
					/>
				</FormGroup>

				<FormGroup>
					<Label htmlFor="mcp-tools">Tools (comma-separated)</Label>
					<Input
						id="mcp-tools"
						placeholder="read_file, write_file, list_dir"
						value={toolsRaw}
						onChange={(e) => setToolsRaw(e.target.value)}
					/>
				</FormGroup>

				<FormGroup>
					<Label htmlFor="mcp-rate-limit">Rate limit (requests per minute)</Label>
					<Input
						id="mcp-rate-limit"
						type="number"
						placeholder="e.g. 60"
						min="1"
						value={rateLimitRpm}
						onChange={(e) => setRateLimitRpm(e.target.value)}
					/>
				</FormGroup>

				<div className="flex items-center gap-3 pt-1">
					<button
						id="mcp-auth"
						type="button"
						role="switch"
						aria-checked={authRequired}
						onClick={() => setAuthRequired((v) => !v)}
						className={[
							"relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-amber-500/30 focus:ring-offset-2 focus:ring-offset-zinc-900",
							authRequired ? "bg-amber-600" : "bg-zinc-700",
						].join(" ")}
					>
						<span
							className={[
								"pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200",
								authRequired ? "translate-x-4" : "translate-x-0",
							].join(" ")}
						/>
					</button>
					<label
						htmlFor="mcp-auth"
						className="text-sm text-zinc-700 dark:text-zinc-300 cursor-pointer select-none"
					>
						Auth required
					</label>
				</div>
			</div>
		</Modal>
	);
}

// ─── MCP Servers Page ─────────────────────────────────────────────────────────

interface McpServersPageProps {
	client: TheAuthApiClient;
}

export function McpServersPage({ client }: McpServersPageProps) {
	const queryClient = useQueryClient();
	const [registerOpen, setRegisterOpen] = useState(false);

	const { data: serversResult, isLoading } = useQuery({
		queryKey: ["mcp-servers"],
		queryFn: () => client.getMcpServers(),
	});

	const registerMutation = useMutation({
		mutationFn: (input: RegisterMcpServerInput) => client.registerMcpServer(input),
		onSuccess: (result) => {
			if (result.success) {
				void queryClient.invalidateQueries({ queryKey: ["mcp-servers"] });
				setRegisterOpen(false);
			}
		},
	});

	const servers = serversResult?.success ? serversResult.data : [];

	return (
		<div>
			<PageHeader
				title="MCP Servers"
				description="Registered Model Context Protocol servers available to agents."
				actions={
					<Button variant="primary" onClick={() => setRegisterOpen(true)}>
						<Plus className="w-3.5 h-3.5" />
						Register Server
					</Button>
				}
			/>

			{isLoading ? (
				<div className="flex items-center justify-center py-16">
					<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
				</div>
			) : servers.length === 0 ? (
				<Table>
					<TableHead>
						<Th>Name</Th>
						<Th>Endpoint</Th>
						<Th>Tools</Th>
						<Th>Auth</Th>
						<Th>Rate limit</Th>
						<Th>Status</Th>
					</TableHead>
					<TableBody>
						<tr>
							<td colSpan={6}>
								<EmptyState
									icon={<Server className="w-6 h-6" />}
									title="No servers registered"
									description="Register an MCP server to make its tools available to agents."
									action={
										<Button variant="primary" onClick={() => setRegisterOpen(true)}>
											<Plus className="w-3.5 h-3.5" />
											Register Server
										</Button>
									}
								/>
							</td>
						</tr>
					</TableBody>
				</Table>
			) : (
				<Table>
					<TableHead>
						<Th>Name</Th>
						<Th>Endpoint</Th>
						<Th>Tools</Th>
						<Th>Auth</Th>
						<Th>Rate limit</Th>
						<Th>Status</Th>
					</TableHead>
					<TableBody>
						{servers.map((server) => (
							<Tr key={server.id}>
								<Td>
									<div className="flex items-center gap-2">
										<div className="w-6 h-6 rounded-md bg-zinc-100 dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 flex items-center justify-center flex-shrink-0">
											<Server className="w-3.5 h-3.5 text-zinc-400" />
										</div>
										<span className="text-sm font-medium text-zinc-900 dark:text-white">
											{server.name}
										</span>
									</div>
								</Td>
								<Td>
									<code className="text-xs font-mono text-zinc-400 max-w-[200px] truncate block">
										{server.endpoint}
									</code>
								</Td>
								<Td>
									{server.tools.length === 0 ? (
										<span className="text-xs text-zinc-600">—</span>
									) : (
										<div className="flex items-center gap-1.5">
											<span className="text-sm text-zinc-700 dark:text-zinc-300 font-medium">
												{server.tools.length}
											</span>
											<span className="text-xs text-zinc-500">
												{server.tools.length === 1 ? "tool" : "tools"}
											</span>
										</div>
									)}
								</Td>
								<Td>
									{server.authRequired ? (
										<Badge variant="gold">Required</Badge>
									) : (
										<Badge variant="gray">None</Badge>
									)}
								</Td>
								<Td>
									{server.rateLimit ? (
										<span className="text-xs font-mono text-zinc-300">
											{server.rateLimit.rpm} rpm
										</span>
									) : (
										<span className="text-xs text-zinc-600">—</span>
									)}
								</Td>
								<Td>
									<Badge variant={statusVariant(server.status)}>
										<StatusDot variant={statusVariant(server.status)} />
										{server.status}
									</Badge>
								</Td>
							</Tr>
						))}
					</TableBody>
				</Table>
			)}

			<RegisterMcpServerModal
				open={registerOpen}
				onClose={() => setRegisterOpen(false)}
				onSubmit={(input) => registerMutation.mutate(input)}
				loading={registerMutation.isPending}
			/>
		</div>
	);
}
