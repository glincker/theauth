// Factories

// Assertions
export {
	expectAuthenticated,
	expectPermissionDenied,
	expectUnauthenticated,
} from "./assertions.js";
export {
	createMockAgent,
	createMockPermission,
	createMockSession,
	createMockUser,
} from "./factories.js";
// Mock React provider (component / browser tests)
export type { MockTheAuthProviderProps } from "./mock-provider.js";
export { MockTheAuthProvider } from "./mock-provider.js";
// Mock auth server (server-side / Node tests)
export type { MockAuthAdapter, MockAuthServer, MockResolvedUser } from "./mock-server.js";
export { createMockAuthServer, MOCK_USER_ID_HEADER } from "./mock-server.js";
