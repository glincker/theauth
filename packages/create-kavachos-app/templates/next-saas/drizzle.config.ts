import { defineConfig } from "drizzle-kit";

export default defineConfig({
	dialect: "__DB_DRIVER__" === "pg" ? "postgresql" : "sqlite",
	schema: "./src/lib/schema.ts",
	out: "./drizzle",
	dbCredentials: {
		url: process.env["DATABASE_URL"] ?? "file:./kavach.db",
	},
});
