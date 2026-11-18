/** Every tunable default lives here; callers override through CollectOptions. */
export const DEFAULTS = {
	/** Per-source timeout in milliseconds. */
	sourceTimeoutMs: 250,
	/** Length of the generated nonce in characters (16 to 64 allowed by the schema). */
	nonceLength: 22,
	/** Bucket size for screen sides in CSS pixels. */
	screenBucketPx: 100,
	/** Largest core count reported. */
	maxCores: 64,
	/** Upper bound on automation globals counted, matches the schema maximum. */
	maxAutomationGlobals: 32,
	/** Languages counted at most, matches the schema maximum. */
	maxLangCount: 20,
	/** Touch points counted at most, matches the schema maximum. */
	maxTouchPoints: 10,
} as const;
