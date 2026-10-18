export type CheckStatus = "pass" | "fail" | "skip";

/** RFC 2119 weight: a failing "must" turns the badge red. */
export type Severity = "must" | "should" | "may";

export interface CheckOutcome {
	status: CheckStatus;
	/** One plain sentence: why it passed, failed or was skipped. */
	summary: string;
	/** Raw observations (status codes, headers, values) backing the verdict. */
	evidence?: Record<string, unknown>;
}

export interface CheckMeta {
	id: string;
	title: string;
	/** Spec reference, for example "RFC 8414 section 3". */
	spec: string;
	severity: Severity;
}

export interface CheckResult extends CheckMeta, CheckOutcome {
	durationMs: number;
}

export interface Options {
	/** Server under test: an authorization server issuer or a resource server URL. */
	target: string;
	/** Protected resource URL to probe for the 401 challenge. Default: discovered. */
	resource?: string;
	/** Use this client instead of registering one through DCR. */
	clientId?: string;
	/** Redirect URI registered for `clientId`. */
	redirectUri?: string;
	/** Optional access token. Enables the audience check; never sent anywhere else. */
	accessToken?: string;
	/** Optional refresh token. Enables rotation and reuse detection. It gets consumed. */
	refreshToken?: string;
	timeoutMs: number;
	/** "guard" runs the remote guard protocol checks against a vendor endpoint. */
	mode?: "oauth" | "guard";
	/** HMAC secret for guard mode. Used to sign probes, never printed. */
	guardSecret?: string;
}

export interface Summary {
	pass: number;
	fail: number;
	skip: number;
	/** Failed checks with severity "must". */
	mustFailed: number;
}

export interface Report {
	tool: string;
	version: string;
	target: string;
	generatedAt: string;
	summary: Summary;
	results: CheckResult[];
}

export interface ShieldsBadge {
	schemaVersion: 1;
	label: string;
	message: string;
	color: string;
}
