import { describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createDbMigrationStore } from "../src/migrate/db-store.js";
import { importUsers } from "../src/migrate/import-users.js";
import { createMemoryMigrationStore } from "../src/migrate/memory-store.js";
import { getMigrationStatus } from "../src/migrate/status.js";
import type { ImportSource } from "../src/migrate/types.js";

const BCRYPT = "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234";

const AUTH0_USERS = JSON.stringify([
	{
		user_id: "auth0|u1",
		email: "Ada@Example.test",
		email_verified: true,
		name: "Ada Test",
		identities: [
			{ provider: "auth0", user_id: "u1" },
			{ provider: "google-oauth2", user_id: "g-1" },
		],
		app_metadata: { plan: "pro" },
	},
	{ user_id: "auth0|u2", email: "bob@example.test", email_verified: false },
	{ email: "nouser@example.test" },
]);
const AUTH0_HASHES = `{"email":"ada@example.test","passwordHash":"${BCRYPT}"}\n`;

const KEYCLOAK = JSON.stringify({
	realm: "demo",
	users: [
		{
			id: "kc-1",
			username: "ada",
			email: "ada@example.test",
			emailVerified: true,
			firstName: "Ada",
			lastName: "Test",
			credentials: [
				{
					type: "password",
					secretData: '{"value":"AAEC","salt":"AwQF"}',
					credentialData: '{"hashIterations":27500,"algorithm":"pbkdf2-sha256"}',
				},
			],
			federatedIdentities: [{ identityProvider: "github", userId: "gh-9" }],
		},
		{
			id: "kc-2",
			email: "old@example.test",
			credentials: [
				{
					type: "password",
					hashedSaltedValue: "AAEC",
					salt: "AwQF",
					hashIterations: 20000,
					algorithm: "pbkdf2",
				},
			],
		},
		{
			id: "kc-3",
			email: "weird@example.test",
			credentials: [
				{
					type: "password",
					secretData: '{"value":"AA","salt":"AA"}',
					credentialData: '{"hashIterations":1,"algorithm":"argon2"}',
				},
			],
		},
	],
});

const CLERK_CSV = `id,first_name,last_name,username,primary_email_address,verified_email_addresses,password_digest,password_hasher
user_1,Ada,Test,ada,ada@example.test,ada@example.test,${BCRYPT},bcrypt
user_2,Bob,,bob,bob@example.test,,,
user_3,Cy,,cy,cy@example.test,cy@example.test,xyz,md5
`;

const BETTER_AUTH = JSON.stringify({
	user: [{ id: "ba-1", name: "Ada", email: "ada@example.test", emailVerified: true }],
	account: [
		{ userId: "ba-1", providerId: "credential", accountId: "ba-1", password: "0a0b0c:0102" },
		{ userId: "ba-1", providerId: "github", accountId: "gh-1" },
	],
	session: [],
});

const NEXTAUTH = JSON.stringify({
	users: [
		{ id: "na-1", name: "Ada", email: "ada@example.test", emailVerified: "2026-01-01T00:00:00Z" },
		{ id: "na-2", email: "bob@example.test", emailVerified: null, password: BCRYPT },
	],
	accounts: [{ userId: "na-1", type: "oauth", provider: "github", providerAccountId: "gh-2" }],
});

const GENERIC_CSV = `uid,mail,verified,full_name,pw\n7,ada@example.test,true,Ada,${BCRYPT}\n8,bob@example.test,false,Bob,\n`;

interface Case {
	source: ImportSource;
	text: string;
	extra?: { passwordHashes?: string; mapping?: Record<string, string> };
	total: number;
	errors: number;
	withHash: number;
}

const CASES: Case[] = [
	{
		source: "auth0",
		text: AUTH0_USERS,
		extra: { passwordHashes: AUTH0_HASHES },
		total: 3,
		errors: 1,
		withHash: 1,
	},
	{ source: "keycloak", text: KEYCLOAK, total: 3, errors: 0, withHash: 2 },
	{ source: "clerk", text: CLERK_CSV, total: 3, errors: 0, withHash: 1 },
	{ source: "better-auth", text: BETTER_AUTH, total: 1, errors: 0, withHash: 1 },
	{ source: "nextauth", text: NEXTAUTH, total: 2, errors: 0, withHash: 1 },
	{
		source: "generic",
		text: GENERIC_CSV,
		extra: {
			mapping: {
				externalId: "uid",
				email: "mail",
				emailVerified: "verified",
				name: "full_name",
				passwordHash: "pw",
			},
		},
		total: 2,
		errors: 0,
		withHash: 1,
	},
];

describe("importers", () => {
	for (const c of CASES) {
		it(`${c.source}: dry run reports, then import writes, then rerun is idempotent`, async () => {
			const store = createMemoryMigrationStore();
			const opts = {
				source: c.source,
				stream: c.text,
				store,
				parseOptions: { passwordHashes: c.extra?.passwordHashes, mapping: c.extra?.mapping },
			};
			const dry = await importUsers({ ...opts, dryRun: true });
			expect(dry.success).toBe(true);
			if (!dry.success) return;
			expect(dry.data.created).toBe(c.total - c.errors);
			expect(dry.data.errors).toBe(c.errors);
			expect(dry.data.withPasswordHash).toBe(c.withHash);
			expect(store.users.size).toBe(0);

			const real = await importUsers({ ...opts, dryRun: false });
			expect(real.success && real.data.created).toBe(c.total - c.errors);
			expect(store.users.size).toBe(c.total - c.errors);

			const again = await importUsers({ ...opts, dryRun: false });
			expect(again.success && again.data.created).toBe(0);
			expect(again.success && again.data.skipped).toBe(c.total - c.errors);
			expect(store.users.size).toBe(c.total - c.errors);
		});
	}

	it("maps linked accounts, verification and names", async () => {
		const store = createMemoryMigrationStore();
		await importUsers({ source: "auth0", stream: AUTH0_USERS, store, dryRun: false });
		const u = store.users.get([...store.users.keys()][0] as string)?.imported;
		expect(u?.email).toBe("ada@example.test");
		expect(u?.emailVerified).toBe(true);
		expect(u?.linkedAccounts).toEqual([{ provider: "google-oauth2", providerAccountId: "g-1" }]);
	});

	it("keycloak credentials keep iterations, salt and algorithm", async () => {
		const store = createMemoryMigrationStore();
		await importUsers({ source: "keycloak", stream: KEYCLOAK, store, dryRun: false });
		const hash = await store.getPasswordHash([...store.users.keys()][0] as string);
		expect(hash).toBe("pbkdf2-sha256$27500$AwQF$AAEC");
	});

	it("reports an email conflict and keeps the existing user", async () => {
		const store = createMemoryMigrationStore();
		await store.createUser(
			{
				externalId: "x",
				email: "ada@example.test",
				emailVerified: true,
				name: null,
				linkedAccounts: [],
				metadata: {},
			},
			"other",
		);
		const r = await importUsers({ source: "clerk", stream: CLERK_CSV, store, dryRun: false });
		expect(r.success && r.data.conflicts).toBe(1);
		expect(r.success && r.data.created).toBe(2);
		const failing = await importUsers({
			source: "clerk",
			stream: CLERK_CSV,
			store,
			dryRun: true,
			onConflict: "fail",
		});
		expect(failing.success).toBe(false);
	});

	it("update policy adopts the existing account by email", async () => {
		const store = createMemoryMigrationStore();
		await store.createUser(
			{
				externalId: "x",
				email: "ada@example.test",
				emailVerified: false,
				name: null,
				linkedAccounts: [],
				metadata: {},
			},
			"other",
		);
		const r = await importUsers({
			source: "clerk",
			stream: CLERK_CSV,
			store,
			dryRun: false,
			onConflict: "update",
		});
		expect(r.success && r.data.updated).toBe(1);
	});

	it("reads streams and rejects oversized input", async () => {
		const store = createMemoryMigrationStore();
		async function* chunks(): AsyncGenerator<string> {
			yield AUTH0_USERS.slice(0, 40);
			yield AUTH0_USERS.slice(40);
		}
		const r = await importUsers({ source: "auth0", stream: chunks(), store, dryRun: true });
		expect(r.success && r.data.total).toBe(3);
		const big = await importUsers({ source: "auth0", stream: AUTH0_USERS, store, maxBytes: 10 });
		expect(big.success).toBe(false);
	});

	it("keeps emails, names and hashes out of the report", async () => {
		const store = createMemoryMigrationStore();
		const r = await importUsers({
			source: "auth0",
			stream: AUTH0_USERS,
			store,
			parseOptions: { passwordHashes: AUTH0_HASHES },
		});
		const text = JSON.stringify(r);
		expect(text).not.toContain("example.test");
		expect(text).not.toContain("Ada");
		expect(text).not.toContain("$2b$");
	});

	it("persists through the database store and feeds the status report", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		const store = await createDbMigrationStore(db);
		const first = await importUsers({ source: "clerk", stream: CLERK_CSV, store, dryRun: false });
		expect(first.success && first.data.created).toBe(3);
		const second = await importUsers({ source: "clerk", stream: CLERK_CSV, store, dryRun: false });
		expect(second.success && second.data.skipped).toBe(3);
		const status = await getMigrationStatus(store);
		expect(status.pending).toBe(3);
		expect(JSON.stringify(status)).not.toContain("example.test");
	});
});
