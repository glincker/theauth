/**
 * Human auth adapter system for TheAuth.
 *
 * Lets TheAuth plug into existing auth providers (better-auth, Auth.js,
 * Clerk, or a custom resolver) so that human user identity can be resolved
 * from an incoming HTTP request before agent operations are performed.
 *
 * @example
 * ```typescript
 * import { createKavach } from 'theauth';
 * import { bearerAuth } from 'theauth/auth';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: bearerAuth({ secret: process.env.JWT_SECRET }),
 * });
 *
 * const user = await kavach.resolveUser(request);
 * ```
 */

export type { BearerAuthOptions } from "./adapters/bearer.js";

// Built-in adapters
export { bearerAuth } from "./adapters/bearer.js";
export { customAuth } from "./adapters/custom.js";
export type { HeaderAuthOptions } from "./adapters/header.js";
export { headerAuth } from "./adapters/header.js";
// Additional user/session fields plugin
export type {
	AdditionalFieldsConfig,
	AdditionalFieldsModule,
	FieldDefinition,
	ValidationResult,
} from "./additional-fields.js";
export { additionalFields, createAdditionalFieldsModule } from "./additional-fields.js";
// Admin module
export type { AdminConfig, AdminModule, AdminUser } from "./admin.js";
export { createAdminModule } from "./admin.js";
// Admin plugin (KavachPlugin wrapper)
export { admin } from "./admin-plugin.js";
// Anonymous auth
export type { AnonymousAuthConfig, AnonymousAuthModule } from "./anonymous.js";
export { createAnonymousAuthModule } from "./anonymous.js";
// Anonymous auth plugin (KavachPlugin wrapper)
export { anonymousAuth } from "./anonymous-plugin.js";
// API key management
export type { ApiKey, ApiKeyManagerConfig, ApiKeyManagerModule } from "./api-key-manager.js";
export { createApiKeyManagerModule } from "./api-key-manager.js";
// API key plugin (KavachPlugin wrapper)
export { apiKeys } from "./api-key-plugin.js";
// Captcha integration (reCAPTCHA, hCaptcha, Turnstile)
export type { CaptchaConfig, CaptchaModule, CaptchaVerifyResult } from "./captcha.js";
export { createCaptchaModule } from "./captcha.js";
// Cost attribution and observability
export type {
	BudgetCheckResult,
	CostAlert,
	CostAttributionConfig,
	CostAttributionModule,
	CostReport,
	RecordCostInput,
} from "./cost-attribution.js";
export { createCostAttributionModule } from "./cost-attribution.js";
// Custom session fields plugin
export type { CustomSessionConfig, CustomSessionModule } from "./custom-session.js";
export { createCustomSessionModule, customSession } from "./custom-session.js";
// OAuth Device Authorization Grant (RFC 8628)
export type {
	DeviceAuthConfig,
	DeviceAuthModule,
	DeviceAuthStatus,
	DeviceCodeResponse,
} from "./device-auth.js";
export { createDeviceAuthModule, deviceAuth } from "./device-auth.js";
// Email OTP
export type { EmailOtpConfig, EmailOtpModule } from "./email-otp.js";
export { createEmailOtpModule } from "./email-otp.js";
// Email OTP plugin (KavachPlugin wrapper)
export { emailOtp } from "./email-otp-plugin.js";
// Email verification
export type { EmailVerificationConfig, EmailVerificationModule } from "./email-verification.js";
export { createEmailVerificationModule } from "./email-verification.js";
// Ephemeral sessions (short-lived agent credentials for computer-use agents)
export type {
	CreateEphemeralSessionInput,
	EphemeralSession,
	EphemeralSessionConfig,
	EphemeralSessionModule,
	EphemeralSessionValidateResult,
} from "./ephemeral-sessions.js";
export { createEphemeralSessionModule } from "./ephemeral-sessions.js";
// SSE event streaming
export type {
	EventStreamConfig,
	EventStreamModule,
	EventType,
	StreamEvent,
} from "./event-stream.js";
export { createEventStreamModule, EVENT_TYPES } from "./event-stream.js";
// Agent identity federation (cross-instance auth)
export type {
	FederatedAgent,
	FederationConfig,
	FederationModule,
	FederationToken,
	FederationWellKnown,
	InstanceIdentity,
	IssueFederationTokenInput,
	TrustedInstance,
	TrustLevel,
} from "./federation.js";
export { createFederationModule } from "./federation.js";
// GDPR module (right to erasure + right to portability)
export type { DeleteOptions, DeleteResult, GdprModule, UserDataExport } from "./gdpr.js";
export { createGdprModule } from "./gdpr.js";
// GDPR plugin (KavachPlugin wrapper)
export { gdpr } from "./gdpr-plugin.js";
// Have I Been Pwned password checking
export type { HibpConfig, HibpModule } from "./hibp.js";
export { createHibpModule, HibpApiError, HibpBreachedError } from "./hibp.js";
// JWT session plugin (general-purpose access + refresh token sessions)
export type {
	JwtSessionConfig,
	JwtSessionModule,
	SessionTokens,
	SessionUser,
	VerifiedSession,
} from "./jwt-session.js";
export { createJwtSessionModule } from "./jwt-session.js";
// Last login method tracking
export type {
	LastLoginConfig,
	LastLoginModule,
	LoginEvent,
	LoginMethod,
	RecordLoginInput,
} from "./last-login.js";
export { createLastLoginModule } from "./last-login.js";
// Magic link (passwordless email)
export type { MagicLinkConfig, MagicLinkModule } from "./magic-link.js";
export { createMagicLinkModule } from "./magic-link.js";
// Magic link plugin (KavachPlugin wrapper)
export { magicLink } from "./magic-link-plugin.js";
export { createOAuthModule } from "./oauth/module.js";
// OAuth 2.0 / OIDC provider system
export type { OAuthPluginConfig } from "./oauth/plugin.js";
export { oauth } from "./oauth/plugin.js";
export * from "./oauth/providers/index.js";
export type {
	OAuthAccount,
	OAuthCallbackResult,
	OAuthModule,
	OAuthModuleConfig,
	OAuthProvider,
	OAuthProviderConfig,
	OAuthTokens,
	OAuthUserInfo,
} from "./oauth/types.js";
// OAuth proxy (server-side OAuth for mobile apps)
export type { OAuthProxyConfig, OAuthProxyModule, ProxyTokens } from "./oauth-proxy.js";
export { createOAuthProxyModule, OAuthProxyError } from "./oauth-proxy.js";
// OAuth proxy plugin (KavachPlugin wrapper)
export type { OAuthProxyPluginConfig } from "./oauth-proxy-plugin.js";
export { oauthProxy } from "./oauth-proxy-plugin.js";
// OIDC Provider (TheAuth as an identity provider)
export type {
	AccessTokenClaims,
	AuthorizeParams,
	GetUserClaimsFn,
	JsonWebKeySet,
	OidcClient,
	OidcDiscoveryDocument,
	OidcProviderConfig,
	OidcProviderModule,
	RegisterClientInput,
	TokenParams,
	TokenResponse,
	UserInfoClaims,
} from "./oidc-provider.js";
export { createOidcProviderModule } from "./oidc-provider.js";
// Google One Tap
export type { GoogleUser, OneTapConfig, OneTapModule } from "./one-tap.js";
export { createOneTapModule, OneTapVerifyError } from "./one-tap.js";
// Google One Tap plugin (KavachPlugin wrapper)
export { oneTap } from "./one-tap-plugin.js";
// One-time tokens (email verify, password reset, invitation, custom)
export type {
	CreateTokenInput,
	OneTimeTokenConfig,
	OneTimeTokenModule,
	OneTimeTokenPurpose,
	RevokeTokensResult,
	ValidateTokenResult,
} from "./one-time-token.js";
export { createOneTimeTokenModule } from "./one-time-token.js";
// OpenAPI spec generation
export type {
	EndpointGroup,
	OpenApiComponents,
	OpenApiConfig,
	OpenApiDocument,
	OpenApiInfo,
	OpenApiMediaType,
	OpenApiModule,
	OpenApiOperation,
	OpenApiParameter,
	OpenApiPathItem,
	OpenApiRequestBody,
	OpenApiResponse,
	OpenApiSchema,
	OpenApiSecurityRequirement,
	OpenApiSecurityScheme,
	OpenApiServer,
} from "./openapi.js";
export { createOpenApiModule } from "./openapi.js";
// Organizations + RBAC
export type {
	Organization,
	OrgConfig,
	OrgInvitation,
	OrgMember,
	OrgModule,
	OrgRole,
} from "./organization.js";
export { createOrgModule } from "./organization.js";
// Organization plugin (KavachPlugin wrapper)
export { organization } from "./organization-plugin.js";
// Passkey / WebAuthn authentication
export type { PasskeyConfig, PasskeyCredential, PasskeyModule } from "./passkey.js";
export { createPasskeyModule } from "./passkey.js";
// Passkey plugin (KavachPlugin wrapper)
export { passkey } from "./passkey-plugin.js";
// Password reset (forgot password + reset password flow)
export type { PasswordResetConfig, PasswordResetModule } from "./password-reset.js";
export { createPasswordResetModule } from "./password-reset.js";
// Phone number (SMS OTP) authentication
export type { PhoneAuthConfig, PhoneAuthModule } from "./phone.js";
export { createPhoneAuthModule } from "./phone.js";
// Polar payment integration
export type { PolarConfig, PolarModule, PolarSubscription } from "./polar.js";
export { createPolarModule } from "./polar.js";
// Polar plugin (KavachPlugin wrapper)
export { polar } from "./polar-plugin.js";
// rateLimit plugin (KavachPlugin wrapper with per-endpoint limits and pluggable store)
export type {
	EndpointLimit,
	RateLimitConfig as RateLimitPluginConfig,
	RateLimitStore,
} from "./rate-limit.js";
export { rateLimit } from "./rate-limit.js";
export type { RateLimitMiddlewareOptions } from "./rate-limit-middleware.js";
export { withRateLimit } from "./rate-limit-middleware.js";
// Rate limiting for auth endpoints (lower-level primitives)
export type { RateLimitConfig, RateLimiter, RateLimitResult } from "./rate-limiter.js";
export { createRateLimiter } from "./rate-limiter.js";
// Relationship-Based Access Control (ReBAC) — Zanzibar-inspired
export type {
	CheckParams,
	CheckResult,
	ExpandParams,
	ListObjectsParams,
	ListSubjectsParams,
	PermissionRuleSet,
	ReBACConfig,
	ReBACModule,
	Relationship,
	ResourceNode,
} from "./rebac.js";
export { createReBACModule } from "./rebac.js";
// SCIM 2.0 directory sync (RFC 7644)
export type { ScimConfig, ScimGroup, ScimModule, ScimUser } from "./scim.js";
export { createScimModule } from "./scim.js";
// SCIM plugin (KavachPlugin wrapper)
export { scim } from "./scim-plugin.js";
// Sign In With Ethereum (EIP-4361)
export type { SiweConfig, SiweModule, SiweVerifyResult } from "./siwe.js";
export { createSiweModule, siwe } from "./siwe.js";
// SSO (SAML 2.0 + OIDC)
export type {
	OidcProvider,
	SamlProvider,
	SsoAuditEvent,
	SsoConfig,
	SsoConnection,
	SsoModule,
} from "./sso.js";
export { createSsoModule, SSO_ERROR, SsoError } from "./sso.js";
export type { KVNamespace } from "./stores/kv.js";
export { KVStore, kvStore } from "./stores/kv.js";
// Rate limiting stores
export { MemoryStore } from "./stores/memory.js";
// Stripe payment integration
export type {
	CheckoutOptions,
	StripeConfig,
	StripeModule,
	SubscriptionInfo,
} from "./stripe.js";
export { createStripeModule } from "./stripe.js";
// Stripe plugin (KavachPlugin wrapper)
export { stripe } from "./stripe-plugin.js";
// TOTP two-factor authentication
export type { TotpConfig, TotpModule, TotpSetup } from "./totp.js";
export { createTotpModule } from "./totp.js";
export type { TwoFactorConfig } from "./totp-plugin.js";
// TOTP plugin (KavachPlugin wrapper)
export { twoFactor } from "./totp-plugin.js";
// Trusted device windows for 2FA
export type { TrustedDevice, TrustedDeviceConfig, TrustedDeviceModule } from "./trusted-device.js";
export {
	createTrustedDeviceModule,
	deviceLabelFromRequest,
} from "./trusted-device.js";
export type { AuthAdapter, ResolvedUser } from "./types.js";
// Username + password authentication
export type { UsernameAuthConfig, UsernameAuthModule } from "./username.js";
export { createUsernameAuthModule } from "./username.js";
// Webhook system
export type { WebhookConfig, WebhookEvent, WebhookModule } from "./webhooks.js";
export { createWebhookModule } from "./webhooks.js";
