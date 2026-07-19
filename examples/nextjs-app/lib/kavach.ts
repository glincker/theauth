// Singleton kavach instance for Next.js.
//
// Next.js hot-reloads modules in dev, so we store the instance on `globalThis`
// to avoid re-creating the database connection on every reload.

import { createTheAuth } from "@glinr/theauth";

type KavachInstance = Awaited<ReturnType<typeof createTheAuth>>;

declare global {
	// eslint-disable-next-line no-var
	var __kavach: KavachInstance | undefined;
}

let kavachPromise: Promise<KavachInstance> | undefined;

export function getKavach(): Promise<KavachInstance> {
	if (globalThis.__kavach) {
		return Promise.resolve(globalThis.__kavach);
	}

	if (!kavachPromise) {
		kavachPromise = createTheAuth({
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
			globalThis.__kavach = instance;
			return instance;
		});
	}

	return kavachPromise;
}
