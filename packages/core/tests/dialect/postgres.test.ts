import { defineDialectSuite } from "./suite.js";

// Skipped unless THEAUTH_TEST_PG_URL is set, for example postgres://postgres:postgres@localhost:5432/theauth_test
defineDialectSuite("postgres", "postgres", process.env.THEAUTH_TEST_PG_URL);
