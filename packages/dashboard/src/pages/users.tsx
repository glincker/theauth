import { useQuery } from "@tanstack/react-query";
import { Users } from "lucide-react";
import type { TheAuthApiClient } from "../api/client.js";
import { Badge } from "../components/badge.js";
import { PageHeader } from "../components/layout.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "../components/table.js";
import type { Page } from "../types.js";

// ─── Users Page ───────────────────────────────────────────────────────────────

interface UsersPageProps {
	client: TheAuthApiClient;
	onNavigate: (page: Page) => void;
}

export function UsersPage({ client, onNavigate }: UsersPageProps) {
	const { data: usersResult, isLoading } = useQuery({
		queryKey: ["users"],
		queryFn: () => client.getUsers(),
	});

	const users = usersResult?.success ? usersResult.data : [];

	return (
		<div>
			<PageHeader title="Users" description="Users who own agent identities in this system." />

			{isLoading ? (
				<div className="flex items-center justify-center py-16">
					<div className="w-5 h-5 border-2 border-zinc-300 dark:border-zinc-700 border-t-amber-500 rounded-full animate-spin" />
				</div>
			) : users.length === 0 ? (
				<Table>
					<TableHead>
						<Th>ID</Th>
						<Th>Email</Th>
						<Th>Name</Th>
						<Th>Agents</Th>
						<Th>Created</Th>
					</TableHead>
					<TableBody>
						<tr>
							<td colSpan={5}>
								<EmptyState
									icon={<Users className="w-6 h-6" />}
									title="No users found"
									description="Users will appear here once agents are created."
								/>
							</td>
						</tr>
					</TableBody>
				</Table>
			) : (
				<Table>
					<TableHead>
						<Th>ID</Th>
						<Th>Email</Th>
						<Th>Name</Th>
						<Th>Agents</Th>
						<Th>Created</Th>
					</TableHead>
					<TableBody>
						{users.map((user) => (
							<Tr key={user.id}>
								<Td>
									<code className="text-xs font-mono text-zinc-500">{user.id}</code>
								</Td>
								<Td>
									<span className="text-xs text-zinc-800 dark:text-zinc-200">{user.email}</span>
								</Td>
								<Td>
									<span className="text-xs text-zinc-400">{user.name ?? "—"}</span>
								</Td>
								<Td>
									<button
										type="button"
										onClick={() => onNavigate("agents")}
										className="inline-flex"
										aria-label={`View agents for ${user.email}`}
									>
										<Badge variant={user.agentCount > 0 ? "gold" : "gray"}>{user.agentCount}</Badge>
									</button>
								</Td>
								<Td>
									<span className="text-xs text-zinc-500">
										{new Date(user.createdAt).toLocaleDateString("en-US", {
											year: "numeric",
											month: "short",
											day: "numeric",
										})}
									</span>
								</Td>
							</Tr>
						))}
					</TableBody>
				</Table>
			)}
		</div>
	);
}
