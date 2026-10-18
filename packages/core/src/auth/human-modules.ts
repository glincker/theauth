import type { Database } from "../db/database.js";
import type { RevocationBus } from "../mcp/revocation-bus.js";
import { createObservability } from "../observability/index.js";
import type { SessionManager } from "../session/session.js";
import { createSecondaryStorageResolver } from "../storage/resolve.js";
import type { TheAuthConfig } from "../types.js";
import type { AdminModule } from "./admin.js";
import { createAdminModule } from "./admin.js";
import type { ApiKeyManagerModule } from "./api-key-manager.js";
import { createApiKeyManagerModule } from "./api-key-manager.js";
import { orgPermissionCheck } from "./api-key-scope.js";
import type { CaptchaModule } from "./captcha.js";
import { createCaptchaModule } from "./captcha.js";
import type { EmailOtpModule } from "./email-otp.js";
import { createEmailOtpModule } from "./email-otp.js";
import type { EmailVerificationModule } from "./email-verification.js";
import { createEmailVerificationModule } from "./email-verification.js";
import type { MagicLinkModule } from "./magic-link.js";
import { createMagicLinkModule } from "./magic-link.js";
import { createOneTimeTokenModule } from "./one-time-token.js";
import type { OrgModule } from "./organization.js";
import { createOrgModule } from "./organization.js";
import type { PasskeyModule } from "./passkey.js";
import { createPasskeyModule } from "./passkey.js";
import type { PasswordResetModule } from "./password-reset.js";
import { createPasswordResetModule } from "./password-reset.js";
import type { PhoneAuthModule } from "./phone.js";
import { createPhoneAuthModule } from "./phone.js";
import { recordStepUpOnSession } from "./record-step-up.js";
import type { ModuleRequestDeps } from "./request-user.js";
import { createRequestUserResolver } from "./request-user.js";
import type { SignInGate } from "./sign-in-gate.js";
import type { SsoModule } from "./sso.js";
import { createSsoModule } from "./sso.js";
import type { TotpModule } from "./totp.js";
import { createTotpModule } from "./totp.js";
import type { UsernameAuthModule } from "./username.js";
import { createUsernameAuthModule } from "./username.js";
import type { WebhookModule } from "./webhooks.js";
import { createWebhookModule } from "./webhooks.js";

/**
 * Builds the optional human-auth modules. Each is null unless its config key
 * (and, for session-backed flows, `auth.session`) is present.
 */
export function createHumanAuthModules(
	config: TheAuthConfig,
	db: Database,
	sessionManager: SessionManager | null,
	signInGate: SignInGate,
	revocations?: RevocationBus,
) {
	const magicLinkModule: MagicLinkModule | null =
		config.magicLink && sessionManager
			? createMagicLinkModule(config.magicLink, db, sessionManager, signInGate)
			: null;

	const emailOtpModule: EmailOtpModule | null =
		config.emailOtp && sessionManager
			? createEmailOtpModule(config.emailOtp, db, sessionManager, signInGate)
			: null;

	// Module handlers act on the signed-in user from the auth adapter or session, never a body userId.
	const moduleDeps: ModuleRequestDeps = {
		resolveUser: createRequestUserResolver(db, sessionManager, config.auth?.adapter),
		recordStepUp: (request, method, userId) =>
			recordStepUpOnSession(
				sessionManager,
				config.auth?.session?.cookieName,
				request,
				method,
				userId,
			),
	};

	const totpModule: TotpModule | null = config.totp
		? createTotpModule(config.totp, db, moduleDeps)
		: null;

	const passkeyModule: PasskeyModule | null = config.passkey
		? createPasskeyModule(config.passkey, db, moduleDeps)
		: null;

	const orgModule: OrgModule | null = config.org
		? createOrgModule(config.org, db, moduleDeps)
		: null;

	// SAML request ids and the assertion replay cache live in secondary storage (feature "nonces").
	const ssoModule: SsoModule | null = config.sso
		? createSsoModule(
				{
					...config.sso,
					storage:
						config.sso.storage ??
						createSecondaryStorageResolver(config.secondaryStorage, db).for("nonces"),
				},
				db,
			)
		: null;

	const adminModule: AdminModule | null = config.admin
		? createAdminModule(config.admin, db, sessionManager, revocations)
		: null;

	const apiKeyManagerModule: ApiKeyManagerModule | null = config.apiKeys
		? createApiKeyManagerModule(
				orgModule && !config.apiKeys.grantablePermissions && !config.apiKeys.canGrant
					? { ...config.apiKeys, canGrant: orgPermissionCheck(orgModule) }
					: config.apiKeys,
				db,
				moduleDeps,
			)
		: null;

	const usernameModule: UsernameAuthModule | null =
		config.username && sessionManager
			? createUsernameAuthModule(config.username, db, sessionManager, signInGate, {
					storage: createSecondaryStorageResolver(config.secondaryStorage, db).for("rateLimit"),
					logger: createObservability(config.observability, config.logger).logger,
				})
			: null;

	const oneTimeTokenModule = createOneTimeTokenModule({}, db);
	const passwordResetModule: PasswordResetModule | null =
		config.passwordReset && sessionManager
			? createPasswordResetModule(
					config.passwordReset,
					db,
					sessionManager,
					oneTimeTokenModule,
					signInGate,
				)
			: null;

	const emailVerificationModule: EmailVerificationModule | null = config.emailVerification
		? createEmailVerificationModule(config.emailVerification, db, oneTimeTokenModule, moduleDeps)
		: null;

	const phoneModule: PhoneAuthModule | null =
		config.phone && sessionManager
			? createPhoneAuthModule(config.phone, db, sessionManager, signInGate)
			: null;

	const captchaModule: CaptchaModule | null = config.captcha
		? createCaptchaModule(config.captcha)
		: null;

	const webhookModule: WebhookModule | null =
		config.webhooks && config.webhooks.length > 0 ? createWebhookModule(config.webhooks) : null;

	return {
		magicLinkModule,
		emailOtpModule,
		totpModule,
		passkeyModule,
		orgModule,
		ssoModule,
		adminModule,
		apiKeyManagerModule,
		usernameModule,
		oneTimeTokenModule,
		passwordResetModule,
		emailVerificationModule,
		phoneModule,
		captchaModule,
		webhookModule,
	};
}
