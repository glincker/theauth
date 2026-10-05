import { createTheAuthGoClient } from "@glinr/theauth-client";
import { TheAuthQueryProvider } from "@glinr/theauth-react/query";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { vi } from "vitest";

export interface Reply {
	status: number;
	body?: unknown;
}

export function route(table: Record<string, Reply | Reply[]>) {
	const counts = new Map<string, number>();
	return vi.fn(async (url: string, init: RequestInit) => {
		const action = init.body
			? (JSON.parse(String(init.body)) as { action?: string }).action
			: undefined;
		const key =
			action && `${init.method} ${url}#${action}` in table
				? `${init.method} ${url}#${action}`
				: `${init.method} ${url}`;
		const entry = table[key];
		const n = counts.get(key) ?? 0;
		counts.set(key, n + 1);
		const r = (Array.isArray(entry) ? (entry[n] ?? entry[entry.length - 1]) : entry) ?? {
			status: 404,
			body: { code: "not_found", message: "nope" },
		};
		return {
			ok: r.status < 300,
			status: r.status,
			headers: new Headers(),
			text: () => Promise.resolve(r.body === undefined ? "" : JSON.stringify(r.body)),
		};
	});
}

export const calls = (f: ReturnType<typeof route>) =>
	f.mock.calls.map(([url, init]) => `${init.method} ${url}`);

export function renderWith(ui: ReactNode, fetchFn: ReturnType<typeof route>) {
	const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	const client = createTheAuthGoClient({ fetch: fetchFn as unknown as typeof fetch });
	return render(
		<QueryClientProvider client={qc}>
			<TheAuthQueryProvider client={client}>{ui}</TheAuthQueryProvider>
		</QueryClientProvider>,
	);
}

export const errors = (code: string) => `err:${code}`;
