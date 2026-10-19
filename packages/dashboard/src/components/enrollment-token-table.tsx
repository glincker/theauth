import { KeyRound } from "lucide-react";
import type { EnrollmentTokenSummary } from "../api/device-types.js";
import { Badge } from "./badge.js";
import { Button } from "./button.js";
import { EmptyState, Table, TableBody, TableHead, Td, Th, Tr } from "./table.js";

function tone(status: EnrollmentTokenSummary["status"]): "green" | "red" | "yellow" | "gray" {
	if (status === "active") return "green";
	if (status === "revoked") return "red";
	return "gray";
}

interface Props {
	tokens: EnrollmentTokenSummary[];
	busyId?: string | null;
	onRevoke: (token: EnrollmentTokenSummary) => void;
}

/** Enrollment tokens with usage and state. The plaintext is not listed, only shown once at creation. */
export function EnrollmentTokenTable({ tokens, busyId, onRevoke }: Props) {
	return (
		<Table>
			<TableHead>
				<Th>Token</Th>
				<Th>Owner</Th>
				<Th>Uses</Th>
				<Th>Status</Th>
				<Th>Expires</Th>
				<Th>
					<span className="sr-only">Actions</span>
				</Th>
			</TableHead>
			<TableBody>
				{tokens.length === 0 ? (
					<tr>
						<td colSpan={6}>
							<EmptyState
								icon={<KeyRound className="w-6 h-6" />}
								title="No enrollment tokens"
								description="Tokens you create appear here with their usage. The secret itself is shown once."
							/>
						</td>
					</tr>
				) : (
					tokens.map((token) => (
						<Tr key={token.id}>
							<Td>
								<span className="text-xs">{token.kind}</span>
								<span className="block text-[10px] font-mono text-zinc-500">{token.id}</span>
							</Td>
							<Td>
								<span className="text-xs">{token.ownerId}</span>
							</Td>
							<Td>
								<span className="text-xs font-mono">
									{token.uses} / {token.maxUses}
								</span>
							</Td>
							<Td>
								<Badge variant={tone(token.status)}>{token.status.replace("_", " ")}</Badge>
							</Td>
							<Td>
								<span className="text-xs font-mono">
									{new Date(token.expiresAt).toLocaleString()}
								</span>
							</Td>
							<Td>
								<div className="flex justify-end">
									{token.status === "active" && (
										<Button
											size="sm"
											variant="danger"
											disabled={busyId === token.id}
											onClick={() => onRevoke(token)}
											aria-label={`Revoke token ${token.id}`}
										>
											Revoke
										</Button>
									)}
								</div>
							</Td>
						</Tr>
					))
				)}
			</TableBody>
		</Table>
	);
}
