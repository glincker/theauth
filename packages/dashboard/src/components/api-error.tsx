import type { ApiResult } from "../api/types.js";

/** Shows why a page has no data, e.g. the API serves no route for it. Renders nothing on success. */
export function ApiErrorNotice({ result }: { result: ApiResult<unknown> | undefined }) {
	if (!result || result.success) return null;
	return (
		<div role="alert" className="bg-red-950/30 border border-red-800/50 rounded-xl p-5 mb-4">
			<p className="text-sm text-red-400">{result.error.message}</p>
			<p className="text-xs text-red-500 mt-1 font-mono">{result.error.code}</p>
		</div>
	);
}
