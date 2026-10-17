/**
 * Human auth adapter system for TheAuth.
 * Lets TheAuth plug into existing auth providers (better-auth, Auth.js, Clerk, or a custom resolver) so that human user identity can be resolved from an incoming HTTP request before agent operations are performed.
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { bearerAuth } from '@glinr/theauth/auth';
 *
 * const theauth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 *   auth: bearerAuth({ secret: process.env.JWT_SECRET }),
 * });
 *
 * const user = await theauth.resolveUser(request);
 * ```
 */

export type {
	PostmarkConfig,
	ResendConfig,
	SendGridConfig,
	SesConfig,
	SmtpConfig,
} from "../email/index.js";
export { postmark, resend, sendgrid, ses, smtp } from "../email/index.js";
export * from "../storage/index.js";
export type { BearerAuthOptions } from "./adapters/bearer.js";
export { bearerAuth } from "./adapters/bearer.js";
export { customAuth } from "./adapters/custom.js";
export type { HeaderAuthOptions } from "./adapters/header.js";
export { headerAuth } from "./adapters/header.js";
export type {
	AdditionalFieldsConfig,
	AdditionalFieldsModule,
	FieldDefinition,
	ValidationResult,
} from "./additional-fields.js";
export { additionalFields, createAdditionalFieldsModule } from "./additional-fields.js";
export type { AdminConfig, AdminModule, AdminUser } from "./admin.js";
export { createAdminModule } from "./admin.js";
export { admin } from "./admin-plugin.js";
export type {
	AgentRegistrationConfig,
	AgentRegistrationEvent,
	AgentRegistrationModule,
	CreatedRegistrationToken,
	CreateRegistrationTokenInput,
	RedeemInput,
	RegistrationTokenRecord,
	RegistrationTokenStatus,
} from "./agent-registration.js";
export { createAgentRegistrationModule } from "./agent-registration.js";
export type { AgentRegistrationPluginConfig } from "./agent-registration-plugin.js";
export { agentRegistration } from "./agent-registration-plugin.js";
export type { AnonymousAuthConfig, AnonymousAuthModule } from "./anonymous.js";
export { createAnonymousAuthModule } from "./anonymous.js";
// Anonymous auth plugin (TheAuthPlugin wrapper)
export { anonymousAuth } from "./anonymous-plugin.js";
export type { ApiKey, ApiKeyManagerConfig, ApiKeyManagerModule } from "./api-key-manager.js";
export { createApiKeyManagerModule } from "./api-key-manager.js";
// API key plugin (TheAuthPlugin wrapper)
export { apiKeys } from "./api-key-plugin.js";
// Captcha integration (reCAPTCHA, hCaptcha, Turnstile)
export type { CaptchaConfig, CaptchaModule, CaptchaVerifyResult } from "./captcha.js";
export { createCaptchaModule } from "./captcha.js";
export type { TrustedProxyConfig } from "./client-ip.js";
export { resolveClientIp } from "./client-ip.js";
export type {
	BudgetCheckResult,
	CostAlert,
	CostAttributionConfig,
	CostAttributionModule,
	CostReport,
	RecordCostInput,
} from "./cost-attribution.js";
export { createCostAttributionModule } from "./cost-attribution.js";
export type { CustomSessionConfig, CustomSessionModule } from "./custom-session.js";
export { createCustomSessionModule, customSession } from "./custom-session.js";
// OAuth Device Authorization Grant (RFC 8628)
export type {
	DeviceAuthConfig,
	DeviceAuthEvent,
	DeviceAuthModule,
	DeviceAuthPluginConfig,
	DeviceAuthStatus,
	DeviceCodeRequest,
	DeviceCodeResponse,
	DeviceGrantContext,
	DeviceTokenGrant,
} from "./device-auth.js";
export {
	createDeviceAuthModule,
	DEVICE_CODE_GRANT_TYPE,
	DeviceAuthError,
	deviceAuth,
} from "./device-auth.js";
export type { EmailOtpConfig, EmailOtpModule } from "./email-otp.js";
export { createEmailOtpModule } from "./email-otp.js";
// Email OTP plugin (TheAuthPlugin wrapper)
export { emailOtp } from "./email-otp-plugin.js";
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
export type {
	EventStreamConfig,
	EventStreamModule,
	EventType,
	StreamEvent,
} from "./event-stream.js";
export { createEventStreamModule, EVENT_TYPES } from "./event-stream.js";
export type {
	BackChannelLogoutReceiver,
	BackChannelLogoutReceiverConfig,
	EndSessionContext,
	EndSessionHandler,
	EndSessionHandlerConfig,
	EndSessionUrlParams,
	LogoutClient,
	LogoutReplayStore,
	LogoutTokenClaims,
	SendBackChannelLogoutParams,
} from "./federated-logout.js";
export {
	BACKCHANNEL_LOGOUT_EVENT,
	buildEndSessionUrl,
	createBackChannelLogoutReceiver,
	createEndSessionHandler,
	sendBackChannelLogout,
} from "./federated-logout.js";
// Federated logout: RP-initiated end_session and OIDC back-channel logout
export type { SessionRevoker, SessionRevokerOptions } from "./federated-logout-sessions.js";
export { createSessionRevoker } from "./federated-logout-sessions.js";
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
export type {
	LastLoginConfig,
	LastLoginModule,
	LoginEvent,
	LoginMethod,
	RecordLoginInput,
} from "./last-login.js";
export { createLastLoginModule } from "./last-login.js";
export type { MagicLinkConfig, MagicLinkModule } from "./magic-link.js";
export { createMagicLinkModule } from "./magic-link.js";
// Magic link plugin (TheAuthPlugin wrapper)
export { magicLink } from "./magic-link-plugin.js";
export type {
	OAuthAccessToken,
	OAuthLinkedAccount,
	OAuthTokenEncryptionConfig,
	OAuthTokenErrorCode,
} from "./oauth/index.js";
export { OAuthRefreshError, OAuthTokenError } from "./oauth/index.js";
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
// OAuth proxy plugin (TheAuthPlugin wrapper)
export type { OAuthProxyPluginConfig } from "./oauth-proxy-plugin.js";
export { oauthProxy } from "./oauth-proxy-plugin.js";
export type {
	ClientLogoutConfig,
	FanOutResult,
	OidcLogoutConfig,
	OidcLogoutModule,
} from "./oidc-logout.js";
export { deriveSid } from "./oidc-logout.js";
export { oidcLogout } from "./oidc-logout-plugin.js";
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
export type { GoogleUser, OneTapConfig, OneTapModule } from "./one-tap.js";
export { createOneTapModule, OneTapVerifyError } from "./one-tap.js";
// Google One Tap plugin (TheAuthPlugin wrapper)
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
// Organization plugin (TheAuthPlugin wrapper)
export { organization } from "./organization-plugin.js";
// Unified OTP service (email + SMS) and senders
export type { OtpSendInput, OtpService, OtpServiceConfig, OtpVerifyInput } from "./otp.js";
export { createOtpService, generateOtpCode } from "./otp.js";
export type { OtpRoutesConfig } from "./otp-plugin.js";
export { otpRoutes } from "./otp-plugin.js";
export type {
	EmailOtpSenderOptions,
	OtpChannel,
	OtpMessage,
	OtpPurpose,
	OtpSender,
	TwilioSenderConfig,
} from "./otp-senders.js";
export { consoleOtpSender, emailOtpSender, twilioOtpSender } from "./otp-senders.js";
export type { PasskeyConfig, PasskeyCredential, PasskeyModule } from "./passkey.js";
export { createPasskeyModule } from "./passkey.js";
export { passkey } from "./passkey-plugin.js";
export type { PasskeyTwoFactorFactor, PasskeyTwoFactorOptions } from "./passkey-second-factor.js";
export { createPasskeyTwoFactorFactor } from "./passkey-second-factor.js";
// Password reset (forgot password + reset password flow)
export type { PasswordResetConfig, PasswordResetModule } from "./password-reset.js";
export { createPasswordResetModule } from "./password-reset.js";
// Phone number (SMS OTP) authentication
export type { PhoneAuthConfig, PhoneAuthModule } from "./phone.js";
export { createPhoneAuthModule } from "./phone.js";
export type { PolarConfig, PolarModule, PolarSubscription } from "./polar.js";
export { createPolarModule } from "./polar.js";
export { polar } from "./polar-plugin.js";
// rateLimit plugin (TheAuthPlugin wrapper with per-endpoint limits and pluggable store)
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
// Relationship-Based Access Control (ReBAC), Zanzibar-inspired
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
export { scim } from "./scim-plugin.js";
export type {
	CreateSignInGateOptions,
	EvaluateSignInGateInput,
	PasswordChangeCompletion,
	PasswordChanger,
	SignInGate,
	SignInGateConfig,
	SignInGateContext,
	SignInGateDecision,
	SignInGateTrustedDeviceConfig,
	SignInMethod,
	TrustedDeviceCookie,
	TwoFactorCompletion,
	TwoFactorFactor,
} from "./sign-in-gate.js";
export {
	createSignInGate,
	evaluateSignInGate,
	SIGN_IN_METHODS,
	SignInGateError,
	signInGateRedirect,
	signInGateResponse,
} from "./sign-in-gate.js";
export { signInGatePlugin } from "./sign-in-gate-plugin.js";
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
export { MemoryStore } from "./stores/memory.js";
export type {
	CheckoutOptions,
	StripeConfig,
	StripeModule,
	SubscriptionInfo,
} from "./stripe.js";
export { createStripeModule } from "./stripe.js";
export { stripe } from "./stripe-plugin.js";
export type { TotpConfig, TotpModule, TotpSetup } from "./totp.js";
export { createTotpModule } from "./totp.js";
export type { TwoFactorConfig, TwoFactorOtpConfig } from "./totp-plugin.js";
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
export type { WebhookConfig, WebhookEvent, WebhookModule } from "./webhooks.js";
export { createWebhookModule } from "./webhooks.js";
