/**
 * Singleton TheAuth instance for the marquee demo.
 * Uses in-memory SQLite, state resets on cold start (acceptable for a demo).
 */

import type { TheAuth } from "@glinr/theauth";
import { createTheAuth } from "@glinr/theauth";

let instance: TheAuth | null = null;

export async function getTheAuth(): Promise<TheAuth> {
	if (instance) return instance;

	instance = await createTheAuth({
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
