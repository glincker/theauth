/**
 * Supabase Auth and WorkOS importers. Fixtures follow the vendors' documented shapes:
 * Supabase `auth.users` and `auth.identities` columns (bcrypt in `encrypted_password`),
 * WorkOS List users response and User object (https://workos.com/docs/reference/authkit/user).
 */
import { describe, expect, it } from "vitest";
import { importUsers } from "../src/migrate/import-users.js";
import { createMemoryMigrationStore } from "../src/migrate/memory-store.js";
import { getParser } from "../src/migrate/sources/index.js";

const BCRYPT = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234";
const ID1 = "8c1f6a52-0000-4000-8000-000000000001";
const ID2 = "8c1f6a52-0000-4000-8000-000000000002";
const ID3 = "8c1f6a52-0000-4000-8000-000000000003";

const SUPABASE_JSON = JSON.stringify([
	{
		id: ID1,
		email: "Ada@Example.test",
		encrypted_password: BCRYPT,
		email_confirmed_at: "2026-01-02T03:04:05.000Z",
		phone: "",
		raw_user_meta_data: { full_name: "Ada Test" },
		raw_app_meta_data: { provider: "email", providers: ["email", "github"] },
		identities: [
			{ provider: "email", provider_id: ID1 },
			{ provider: "github", provider_id: "gh-9" },
		],
	},
	{ id: ID2, email: "social@example.test", encrypted_password: "", email_confirmed_at: null },
	{ id: ID3, email: "odd@example.test", encrypted_password: "plaintext-not-a-hash" },
	{ email: "noid@example.test" },
]);

describe("supabase importer", () => {
	it("maps users, bcrypt hashes, identities and metadata from JSON", () => {
		const out = getParser("supabase").parse(SUPABASE_JSON);
		expect(out.users).toHaveLength(3);
		const ada = out.users[0];
		expect(ada?.email).toBe("ada@example.test");
		expect(ada?.emailVerified).toBe(true);
		expect(ada?.name).toBe("Ada Test");
		expect(ada?.passwordHash).toEqual({ algorithm: "bcrypt", hash: BCRYPT });
		expect(ada?.linkedAccounts).toEqual([{ provider: "github", providerAccountId: "gh-9" }]);
		expect(out.users[1]?.emailVerified).toBe(false);
		expect(out.users[1]?.passwordHash).toBeUndefined();
		expect(out.users[2]?.passwordHash).toBeUndefined();
		expect(out.issues.map((i) => i.code).sort()).toEqual(["MISSING_FIELD", "UNSUPPORTED_HASHER"]);
	});

	it("merges the LEFT JOIN auth.identities CSV shape into one user", () => {
		const csv = [
			"id,email,encrypted_password,email_confirmed_at,raw_user_meta_data,provider,provider_id",
			`${ID1},ada@example.test,${BCRYPT},2026-01-02 03:04:05+00,"{""name"":""Ada""}",email,${ID1}`,
			`${ID1},ada@example.test,${BCRYPT},2026-01-02 03:04:05+00,"{""name"":""Ada""}",google,g-1`,
			`${ID1},ada@example.test,${BCRYPT},2026-01-02 03:04:05+00,"{""name"":""Ada""}",google,g-1`,
		].join("\n");
		const out = getParser("supabase").parse(csv);
		expect(out.users).toHaveLength(1);
		expect(out.users[0]?.name).toBe("Ada");
		expect(out.users[0]?.linkedAccounts).toEqual([
			{ provider: "google", providerAccountId: "g-1" },
		]);
		expect(out.users[0]?.passwordHash?.algorithm).toBe("bcrypt");
	});

	it("dry run then import then rerun is idempotent", async () => {
		const store = createMemoryMigrationStore();
		const opts = { source: "supabase" as const, stream: SUPABASE_JSON, store };
		const dry = await importUsers({ ...opts, dryRun: true });
		expect(dry.success && dry.data.created).toBe(3);
		expect(dry.success && dry.data.withPasswordHash).toBe(1);
		expect(store.users.size).toBe(0);
		await importUsers({ ...opts, dryRun: false });
		const again = await importUsers({ ...opts, dryRun: false });
		expect(again.success && again.data.created).toBe(0);
		expect(store.users.size).toBe(3);
	});

	it("never copies hashes or emails into issues", () => {
		const out = getParser("supabase").parse(SUPABASE_JSON);
		expect(JSON.stringify(out.issues)).not.toMatch(/plaintext|example\.test/);
	});
});

const WORKOS_PAGE = JSON.stringify({
	object: "list",
	data: [
		{
			object: "user",
			id: "user_01H",
			first_name: "Ada",
			last_name: "Test",
			email: "Ada@Example.test",
			email_verified: true,
			external_id: "app-77",
			metadata: { plan: "pro" },
			created_at: "2026-01-02T03:04:05.000Z",
			updated_at: "2026-01-02T03:04:05.000Z",
		},
		{ object: "user", id: "user_02H", email: "bob@example.test", email_verified: false },
		{ object: "user", email: "noid@example.test" },
	],
	list_metadata: { before: null, after: null },
});

describe("workos importer", () => {
	it("unwraps a List users page and maps the User object", () => {
		const out = getParser("workos").parse(WORKOS_PAGE);
		expect(out.users).toHaveLength(2);
		const ada = out.users[0];
		expect(ada?.externalId).toBe("user_01H");
		expect(ada?.email).toBe("ada@example.test");
		expect(ada?.emailVerified).toBe(true);
		expect(ada?.name).toBe("Ada Test");
		expect(ada?.metadata).toMatchObject({ external_id: "app-77", metadata: { plan: "pro" } });
		expect(ada?.passwordHash).toBeUndefined();
		expect(out.issues).toHaveLength(1);
	});

	it("reads several pages as newline-delimited JSON and a plain array", () => {
		const pages = `${WORKOS_PAGE}\n${WORKOS_PAGE}`;
		expect(getParser("workos").parse(pages).users).toHaveLength(4);
		const arr = JSON.stringify([{ id: "u1", email: "a@example.test", email_verified: true }]);
		expect(getParser("workos").parse(arr).users).toHaveLength(1);
	});

	it("attaches bcrypt hashes from a support-provided file by email, ignores unknown formats", () => {
		const hashes = [
			`{"email":"ada@example.test","passwordHash":"${BCRYPT}"}`,
			'{"email":"bob@example.test","passwordHash":"not-a-hash"}',
		].join("\n");
		const out = getParser("workos").parse(WORKOS_PAGE, { passwordHashes: hashes });
		expect(out.users[0]?.passwordHash?.algorithm).toBe("bcrypt");
		expect(out.users[1]?.passwordHash).toBeUndefined();
	});

	it("imports through the runner", async () => {
		const store = createMemoryMigrationStore();
		const res = await importUsers({ source: "workos", stream: WORKOS_PAGE, store, dryRun: false });
		expect(res.success && res.data.created).toBe(2);
		expect(res.success && res.data.errors).toBe(1);
	});
});
