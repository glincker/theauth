// Re-export the KavachOS schema so drizzle-kit can pick up migrations for
// the auth tables. Add your application-specific tables alongside these.
export { agentIdentities, auditLogs, delegationChains, sessions, users } from "kavachos/schema";
