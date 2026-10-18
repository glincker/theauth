/**
 * Testing kit for TheAuth policies and agents. Import from `@glinr/theauth/testing`.
 * Nothing here imports vitest or jest.
 */
export type { MatcherResult, PolicyCall } from "./matchers.js";
export { expectAllowed, expectDenied, theauthMatchers } from "./matchers.js";
export type {
	PolicyCase,
	PolicyFailure,
	PolicySuite,
	PolicySuiteAgent,
	PolicySuiteReport,
	RunPolicySuiteOptions,
} from "./suite.js";
export { definePolicySuite, formatPolicyReport, runPolicySuite } from "./suite.js";
export type { SeedAgentInput, TestAuth } from "./test-auth.js";
export { createTestAuth } from "./test-auth.js";
