// Singleton theauth instance for Next.js.
//
// Next.js hot-reloads modules in dev, so we store the instance on `globalThis`
// to avoid re-creating the database connection on every reload.

import { createTheAuth } from "@glinr/theauth";

type TheAuthInstance = Awaited<ReturnType<typeof createTheAuth>>;

declare global {
	// eslint-disable-next-line no-var
	var __theauth: TheAuthInstance | undefined;
}

let theAuthPromise: Promise<TheAuthInstance> | undefined;

export function getTheAuth(): Promise<TheAuthInstance> {
	if (globalThis.__theauth) {
		return Promise.resolve(globalThis.__theauth);
	}

	if (!theAuthPromise) {
		theAuthPromise = createTheAuth({
			database: {
				provider: "sqlite",
				url: process.env.THEAUTH_DB_URL ?? "theauth.db",
			},
			agents: {
				enabled: true,
				maxPerUser: 50,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
		}).then((instance) => {
			globalThis.__theauth = instance;
			return instance;
		});
	}

	return theAuthPromise;
}
