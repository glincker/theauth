/**
 * Singleton TheAuth instance for the demo. In-memory SQLite, so state resets on cold start.
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
