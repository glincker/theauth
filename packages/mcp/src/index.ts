/**
 * Library entry for embedding the admin MCP server in a host process.
 * The CLI lives in bin.ts and is not exported from here.
 */

export type { ApiError, ApiResult, FetchLike, RequestOptions } from "./client.js";
export { ApiClient } from "./client.js";
export type { Config } from "./config.js";
export { ConfigError, DEFAULT_TIMEOUT_MS, loadConfig } from "./config.js";
export type { Logger } from "./logger.js";
export { createLogger } from "./logger.js";
export type { ServerOptions } from "./server.js";
export { createServer, SERVER_NAME, TOOLS } from "./server.js";
export type { Outcome, RegisteredTool, ToolContext, ToolSpec } from "./tools/define.js";
export { defineTool, failure, success } from "./tools/define.js";
