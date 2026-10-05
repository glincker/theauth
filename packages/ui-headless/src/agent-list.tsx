import type { GoAgent } from "@glinr/theauth-client";
import { useAgents } from "@glinr/theauth-react/query";
import type { ReactNode } from "react";
import type { ClassNames, ErrorLabels, RunAction } from "./shared.js";
import { ErrorText, exec, visibleCode } from "./shared.js";

export interface AgentListLabels extends ErrorLabels {
	title: string;
	loading: string;
	empty: string;
	revoked: string;
	status: (status: string) => string;
	lastActive: (iso: string) => string;
	revoke: (agent: GoAgent) => string;
}

type Part = "root" | "list" | "item" | "name" | "meta" | "badge" | "revoke" | "error";

export interface AgentListProps {
	labels: AgentListLabels;
	classNames?: ClassNames<Part>;
	run?: RunAction;
	renderAgent?: (agent: GoAgent, ctx: { revoke: () => void; pending: boolean }) => ReactNode;
}

const STATUS_REVOKED = "revoked";

export function AgentList({ labels, classNames = {}, run, renderAgent }: AgentListProps) {
	const { list, revoke } = useAgents();
	const agents = list.data ?? [];
	const code = visibleCode(list.error, !!run) ?? visibleCode(revoke.error, !!run);

	if (list.isPending) {
		return (
			<section data-part="root" className={classNames.root} aria-busy="true">
				<p role="status">{labels.loading}</p>
			</section>
		);
	}

	return (
		<section data-part="root" className={classNames.root} aria-labelledby="theauth-agents-title">
			<h2 id="theauth-agents-title" data-part="title">
				{labels.title}
			</h2>
			<ErrorText code={code} labels={labels} className={classNames.error} />
			{agents.length === 0 ? (
				<p data-part="empty">{labels.empty}</p>
			) : (
				<ul data-part="list" className={classNames.list}>
					{agents.map((a) => {
						const isRevoked = a.status === STATUS_REVOKED;
						const doRevoke = () => void exec(run, () => revoke.mutateAsync({ id: a.id }));
						const pending = revoke.isPending && revoke.variables?.id === a.id;
						return (
							<li
								key={a.id}
								data-part="item"
								data-status={a.status}
								data-revoked={isRevoked ? "" : undefined}
								className={classNames.item}
							>
								{renderAgent ? (
									renderAgent(a, { revoke: doRevoke, pending })
								) : (
									<>
										<span data-part="name" className={classNames.name}>
											{a.name}
										</span>
										<span data-part="badge" className={classNames.badge}>
											{isRevoked ? labels.revoked : labels.status(a.status)}
										</span>
										<span data-part="meta" className={classNames.meta}>
											{a.clientId}
										</span>
										{a.lastActiveAt && (
											<span data-part="meta" className={classNames.meta}>
												{labels.lastActive(a.lastActiveAt)}
											</span>
										)}
										{!isRevoked && (
											<button
												type="button"
												data-part="revoke"
												className={classNames.revoke}
												aria-label={labels.revoke(a)}
												disabled={pending}
												onClick={doRevoke}
											>
												{labels.revoke(a)}
											</button>
										)}
									</>
								)}
							</li>
						);
					})}
				</ul>
			)}
		</section>
	);
}
