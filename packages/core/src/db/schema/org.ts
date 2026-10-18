import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { json, timestampSec } from "./columns.js";
import { users } from "./core.js";

export const organizations = sqliteTable("theauth_organizations", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	slug: text("slug").notNull().unique(),
	ownerId: text("owner_id")
		.notNull()
		.references(() => users.id),
	metadata: json<Record<string, unknown>>("metadata"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const orgMembers = sqliteTable("theauth_org_members", {
	id: text("id").primaryKey(),
	orgId: text("org_id")
		.notNull()
		.references(() => organizations.id, { onDelete: "cascade" }),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	role: text("role").notNull().default("member"),
	joinedAt: timestampSec("joined_at").notNull(),
});

export const orgInvitations = sqliteTable("theauth_org_invitations", {
	id: text("id").primaryKey(),
	orgId: text("org_id")
		.notNull()
		.references(() => organizations.id, { onDelete: "cascade" }),
	email: text("email").notNull(),
	role: text("role").notNull().default("member"),
	invitedBy: text("invited_by")
		.notNull()
		.references(() => users.id),
	status: text("status", { enum: ["pending", "accepted", "expired"] })
		.notNull()
		.default("pending"),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const orgRoles = sqliteTable("theauth_org_roles", {
	id: text("id").primaryKey(),
	orgId: text("org_id")
		.notNull()
		.references(() => organizations.id, { onDelete: "cascade" }),
	name: text("name").notNull(),
	permissions: json<string[]>("permissions").notNull(),
});
