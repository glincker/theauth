/**
 * Singleton KavachOS instance for the marquee demo.
 * Uses in-memory SQLite, state resets on cold start (acceptable for a demo).
 */

import type { Kavach } from "kavachos";
import { createKavach } from "kavachos";

let instance: Kavach | null = null;

export async function getKavach(): Promise<Kavach> {
	if (instance) return instance;

	instance = await createKavach({
		database: {
			provider: "sqlite",
			url: ":memory:",
		},
		agents: {
			enabled: true,
			maxPerUser: 20,
			tokenExpiry: "1h",
		},
	});

	return instance;
}
