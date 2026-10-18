---
"@glinr/theauth": minor
---

MySQL dialect fixes. The MySQL DDL is now generated from the portable baseline: key, unique, defaulted and referenced `TEXT` columns become `VARCHAR(191)`, inline `REFERENCES` become table level `FOREIGN KEY` clauses (MySQL ignored the inline form), `CREATE INDEX IF NOT EXISTS` loses the unsupported clause, and every table uses InnoDB, utf8mb4 and a binary collation so tokens and ids match exactly. The migration ledger stores `UTC_TIMESTAMP(3)` and the MySQL pool connects with `timezone: "Z"`.

Single use claims (magic link, OTP, one time token, OAuth state, refresh token, session refresh, approvals) no longer call `RETURNING`, which the MySQL query builder lacks. They go through the new `claimCount` helper in `src/db/claim.ts`, which uses `RETURNING` where it exists and the affected row count otherwise. SQLite and Postgres behavior is unchanged.

`provider: "mysql"` still requires `experimental: true`: the gate stays until the contract suite (`THEAUTH_TEST_MYSQL_URL`) has passed against a real MySQL 8.4 server. The suite has not been run against one yet. MySQL migration checksums changed, which affects nobody because no MySQL database could be created before.
