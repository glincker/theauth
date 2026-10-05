import type { GoSession } from "@glinr/theauth-client";
import { useSessions } from "@glinr/theauth-react/query";
import type { ReactNode } from "react";
import type { ClassNames, ErrorLabels, RunAction } from "./shared.js";
import { ErrorText, exec, visibleCode } from "./shared.js";

export interface SessionListLabels extends ErrorLabels {
	title: string;
	loading: string;
	empty: string;
	current: string;
	revokeOthers: string;
	lastSeen: (iso: string) => string;
	revoke: (session: GoSession) => string;
}

type Part =
	| "root"
	| "list"
	| "item"
	| "label"
	| "meta"
	| "badge"
	| "revoke"
	| "revokeOthers"
	| "error";

export interface SessionListProps {
	labels: SessionListLabels;
	classNames?: ClassNames<Part>;
	run?: RunAction;
	/** Replace the default row; call `revoke` from your own control. */
	renderSession?: (session: GoSession, ctx: { revoke: () => void; pending: boolean }) => ReactNode;
}

export function SessionList({ labels, classNames = {}, run, renderSession }: SessionListProps) {
	const { list, revoke, revokeOthers } = useSessions();
	const sessions = list.data ?? [];
	const hasOthers = sessions.some((s) => !s.current);
	const code =
		visibleCode(list.error, !!run) ??
		visibleCode(revoke.error, !!run) ??
		visibleCode(revokeOthers.error, !!run);

	if (list.isPending) {
		return (
			<section data-part="root" className={classNames.root} aria-busy="true">
				<p role="status">{labels.loading}</p>
			</section>
		);
	}

	return (
		<section data-part="root" className={classNames.root} aria-labelledby="theauth-sessions-title">
			<h2 id="theauth-sessions-title" data-part="title">
				{labels.title}
			</h2>
			<ErrorText code={code} labels={labels} className={classNames.error} />
			{sessions.length === 0 ? (
				<p data-part="empty">{labels.empty}</p>
			) : (
				<ul data-part="list" className={classNames.list}>
					{sessions.map((s) => {
						const doRevoke = () => void exec(run, () => revoke.mutateAsync(s.id));
						const pending = revoke.isPending && revoke.variables === s.id;
						return (
							<li
								key={s.id}
								data-part="item"
								data-current={s.current || undefined}
								className={classNames.item}
							>
								{renderSession ? (
									renderSession(s, { revoke: doRevoke, pending })
								) : (
									<>
										<span data-part="label" className={classNames.label}>
											{s.deviceLabel}
										</span>
										<span data-part="meta" className={classNames.meta}>
											{labels.lastSeen(s.lastSeenAt)}
										</span>
										{s.current ? (
											<span data-part="badge" className={classNames.badge}>
												{labels.current}
											</span>
										) : (
											<button
												type="button"
												data-part="revoke"
												className={classNames.revoke}
												aria-label={labels.revoke(s)}
												disabled={pending}
												onClick={doRevoke}
											>
												{labels.revoke(s)}
											</button>
										)}
									</>
								)}
							</li>
						);
					})}
				</ul>
			)}
			{hasOthers && (
				<button
					type="button"
					data-part="revokeOthers"
					className={classNames.revokeOthers}
					disabled={revokeOthers.isPending}
					onClick={() => void exec(run, () => revokeOthers.mutateAsync())}
				>
					{labels.revokeOthers}
				</button>
			)}
		</section>
	);
}
