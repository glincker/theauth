import type { DdlTypes, TaggedStatement } from "./types.js";

/** Baseline DDL for the "org" domain. */
export function orgDdl(t: DdlTypes): TaggedStatement[] {
	const { ts, json, ifne } = t;

	return [
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_organizations (
  id         TEXT    NOT NULL PRIMARY KEY,
  name       TEXT    NOT NULL,
  slug       TEXT    NOT NULL UNIQUE,
  owner_id   TEXT    NOT NULL REFERENCES theauth_users(id),
  metadata   ${json},
  created_at ${ts}   NOT NULL,
  updated_at ${ts}   NOT NULL
)`,
		},

		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_org_members (
  id        TEXT    NOT NULL PRIMARY KEY,
  org_id    TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  user_id   TEXT    NOT NULL REFERENCES theauth_users(id),
  role      TEXT    NOT NULL DEFAULT 'member',
  joined_at ${ts}   NOT NULL,
  UNIQUE(org_id, user_id)
)`,
		},

		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_org_invitations (
  id         TEXT    NOT NULL PRIMARY KEY,
  org_id     TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  email      TEXT    NOT NULL,
  role       TEXT    NOT NULL DEFAULT 'member',
  invited_by TEXT    NOT NULL REFERENCES theauth_users(id),
  status     TEXT    NOT NULL DEFAULT 'pending',
  expires_at ${ts}   NOT NULL,
  created_at ${ts}   NOT NULL
)`,
		},

		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_org_roles (
  id          TEXT    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  permissions ${json} NOT NULL,
  UNIQUE(org_id, name)
)`,
		},
	];
}
