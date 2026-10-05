import type { ApiTokenKind, GoApiToken } from "@glinr/theauth-client";
import { tokenKind, useApiTokens } from "@glinr/theauth-react/query";
import type { ReactNode } from "react";
import type { ClassNames, ErrorLabels, RunAction } from "./shared.js";
import { ErrorText, exec, visibleCode } from "./shared.js";

export interface ApiTokenListLabels extends ErrorLabels {
	title: string;
	loading: string;
	empty: string;
	revoked: string;
	kind: Record<ApiTokenKind, string>;
	lastUsed: (iso: string) => string;
	expires: (iso: string) => string;
	delegatedBy: (userId: string) => string;
	revoke: (token: GoApiToken) => string;
}

type Part = "root" | "list" | "item" | "name" | "meta" | "badge" | "revoke" | "error";

export interface ApiTokenListProps {
	labels: ApiTokenListLabels;
	kind?: ApiTokenKind;
	classNames?: ClassNames<Part>;
	run?: RunAction;
	renderToken?: (token: GoApiToken, ctx: { revoke: () => void; pending: boolean }) => ReactNode;
}

export function ApiTokenList({
	labels,
	kind,
	classNames = {},
	run,
	renderToken,
}: ApiTokenListProps) {
	const { list, revoke } = useApiTokens({ kind });
	const tokens = list.data ?? [];
	const code = visibleCode(list.error, !!run) ?? visibleCode(revoke.error, !!run);

	if (list.isPending) {
		return (
			<section data-part="root" className={classNames.root} aria-busy="true">
				<p role="status">{labels.loading}</p>
			</section>
		);
	}

	return (
		<section data-part="root" className={classNames.root} aria-labelledby="theauth-tokens-title">
			<h2 id="theauth-tokens-title" data-part="title">
				{labels.title}
			</h2>
			<ErrorText code={code} labels={labels} className={classNames.error} />
			{tokens.length === 0 ? (
				<p data-part="empty">{labels.empty}</p>
			) : (
				<ul data-part="list" className={classNames.list}>
					{tokens.map((t) => {
						const k = tokenKind(t);
						const doRevoke = () => void exec(run, () => revoke.mutateAsync(t.id));
						const pending = revoke.isPending && revoke.variables === t.id;
						return (
							<li
								key={t.id}
								data-part="item"
								data-kind={k}
								data-revoked={t.revokedAt ? "" : undefined}
								className={classNames.item}
							>
								{renderToken ? (
									renderToken(t, { revoke: doRevoke, pending })
								) : (
									<>
										<span data-part="name" className={classNames.name}>
											{t.agentName || t.name}
										</span>
										<span data-part="badge" className={classNames.badge}>
											{labels.kind[k]}
										</span>
										<span data-part="meta" className={classNames.meta}>
											{t.hint}
										</span>
										{t.delegatedBy && (
											<span data-part="meta" className={classNames.meta}>
												{labels.delegatedBy(t.delegatedBy)}
											</span>
										)}
										{t.lastUsedAt && (
											<span data-part="meta" className={classNames.meta}>
												{labels.lastUsed(t.lastUsedAt)}
											</span>
										)}
										{t.expiresAt && (
											<span data-part="meta" className={classNames.meta}>
												{labels.expires(t.expiresAt)}
											</span>
										)}
										{t.revokedAt ? (
											<span data-part="badge" className={classNames.badge}>
												{labels.revoked}
											</span>
										) : (
											<button
												type="button"
												data-part="revoke"
												className={classNames.revoke}
												aria-label={labels.revoke(t)}
												disabled={pending}
												onClick={doRevoke}
											>
												{labels.revoke(t)}
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
