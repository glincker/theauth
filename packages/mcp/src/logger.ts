/**
 * stderr-only logger. stdout is the MCP protocol channel, so nothing here may
 * ever write to it. Callers must not pass secrets.
 */
export interface Logger {
	info(message: string): void;
	error(message: string, error?: unknown): void;
}

export function createLogger(sink: (line: string) => void = defaultSink): Logger {
	return {
		info: (message) => sink(`[theauth-mcp] ${message}\n`),
		error: (message, error) => {
			const detail = error instanceof Error ? `: ${error.message}` : "";
			sink(`[theauth-mcp] ERROR ${message}${detail}\n`);
		},
	};
}

function defaultSink(line: string): void {
	process.stderr.write(line);
}
