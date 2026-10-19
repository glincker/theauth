import { describe, expect, it } from "vitest";
import {
	columnOf,
	createModelResolver,
	decodeRow,
	decodeValue,
	encodeValue,
	insertValues,
} from "../src/db/store/kysely/meta.js";

const resolve = createModelResolver();

describe("kysely model metadata", () => {
	it("maps property names to column names and back", () => {
		const meta = resolve("agents");
		expect(meta.tableName).toBe("theauth_agents");
		expect(columnOf(meta, "ownerId").name).toBe("owner_id");
		expect(meta.propertyOf.get("owner_id")).toBe("ownerId");
		expect(meta.primaryKey).toEqual(["id"]);
		expect([...resolve("approvalVotes").primaryKey].sort()).toEqual(["approvalId", "approverId"]);
	});

	it("rejects an unknown model and an unknown field", () => {
		expect(() => resolve("nope" as never)).toThrow(/unknown model/);
		expect(() => columnOf(resolve("agents"), "nope")).toThrow(/no field/);
		expect(() => insertValues(resolve("agents"), { nope: 1 })).toThrow(/no field/);
	});

	it("applies schema defaults to columns the row leaves out, and skips ones without a default", () => {
		const values = new Map(
			insertValues(resolve("agents"), {
				id: "a",
				ownerId: "u",
				name: "n",
				type: "service",
				tokenHash: "h",
				tokenPrefix: "p",
				createdAt: new Date(1000),
				updatedAt: new Date(1000),
				expiresAt: undefined,
			}).map(([col, v]) => [col.name, v]),
		);
		expect(values.get("status")).toBe("active");
		expect(values.get("created_at")).toBe(1);
		expect(values.has("expires_at")).toBe(false);
		expect(values.has("cnf")).toBe(false);
	});

	it("encodes dates, booleans and JSON the way the Drizzle path does, and keeps null", () => {
		const users = resolve("users");
		expect(encodeValue(columnOf(users, "createdAt"), new Date(5999))).toBe(5);
		expect(encodeValue(columnOf(users, "metadata"), { a: 1 })).toBe('{"a":1}');
		expect(encodeValue(columnOf(users, "metadata"), null)).toBeNull();
		expect(encodeValue(columnOf(resolve("magicLinks"), "used"), true)).toBe(1);
	});

	it("decodes what drivers return: bigint strings, parsed or textual JSON, truthy flags, null", () => {
		const users = resolve("users");
		expect(decodeValue(columnOf(users, "createdAt"), "1700000000")).toEqual(
			new Date(1_700_000_000_000),
		);
		expect(decodeValue(columnOf(users, "metadata"), '{"a":1}')).toEqual({ a: 1 });
		expect(decodeValue(columnOf(users, "metadata"), { a: 1 })).toEqual({ a: 1 });
		expect(decodeValue(columnOf(users, "name"), null)).toBeNull();
		expect(decodeValue(columnOf(resolve("magicLinks"), "used"), true)).toBe(true);
		expect(decodeValue(columnOf(resolve("magicLinks"), "used"), 0)).toBe(false);
		expect(decodeValue(columnOf(resolve("emailOtps"), "attempts"), "7")).toBe(7);
		expect(decodeValue(columnOf(resolve("emailOtps"), "attempts"), 7n)).toBe(7);
		expect(decodeRow(users, { id: "x", created_at: "2", unknown_col: 1 })).toEqual({
			id: "x",
			createdAt: new Date(2000),
		});
	});
});
