import type { TranslationKeys } from "../i18n.js";

export const en: TranslationKeys = {
	"auth.invalidCredentials": "Invalid email or password.",
	"auth.emailNotVerified": "Please verify your email address before signing in.",
	"auth.accountLocked": "Your account has been locked. Contact support to unlock it.",
	"auth.rateLimited": "Too many requests. Try again in {{retryAfter}} seconds.",
	"auth.emailAlreadyExists": "An account with that email already exists.",
	"auth.weakPassword":
		"Password is too weak. Use at least 8 characters with a mix of letters, numbers, and symbols.",
	"auth.tokenExpired": "This link has expired. Request a new one.",
	"auth.tokenInvalid": "This link is invalid or has already been used.",
	"auth.unauthorized": "You are not authorized to perform this action.",

	"agent.notFound": "Agent not found.",
	"agent.revoked": "This agent's access has been revoked.",
	"agent.limitExceeded": "Agent limit reached for this account.",
	"agent.permissionDenied": "Agent does not have permission to perform this action.",

	"twoFactor.invalidCode": "Invalid verification code. Check your authenticator app and try again.",
	"twoFactor.alreadyEnabled": "Two-factor authentication is already enabled on this account.",
	"twoFactor.notEnabled": "Two-factor authentication is not enabled on this account.",

	"email.verification.subject": "Verify your email address",
	"email.passwordReset.subject": "Reset your password",
	"email.magicLink.subject": "Your sign-in link",
	"email.otp.subject": "Your one-time code",
	"email.invitation.subject": "You have been invited to join {{orgName}}",
	"email.welcome.subject": "Welcome to {{appName}}",

	"general.serverError": "Something went wrong. Try again later.",
	"general.badRequest": "The request could not be processed.",
	"general.notFound": "The requested resource was not found.",
};
