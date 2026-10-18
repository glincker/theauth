import { defineDialectSuite } from "./suite.js";

// Skipped unless THEAUTH_TEST_MYSQL_URL is set, for example mysql://root:root@localhost:3306/theauth_test
defineDialectSuite("mysql", "mysql", process.env.THEAUTH_TEST_MYSQL_URL);
