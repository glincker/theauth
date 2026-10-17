import type { TranslationKeys } from "../i18n.js";

export const zh: TranslationKeys = {
	"auth.invalidCredentials": "邮箱或密码不正确。",
	"auth.emailNotVerified": "请在登录前验证您的电子邮件地址。",
	"auth.accountLocked": "您的账户已被锁定，请联系支持团队解锁。",
	"auth.rateLimited": "请求过于频繁，请在 {{retryAfter}} 秒后重试。",
	"auth.emailAlreadyExists": "该邮箱地址已注册账户。",
	"auth.weakPassword": "密码强度不足，请使用至少 8 位包含字母、数字和符号的密码。",
	"auth.tokenExpired": "此链接已过期，请重新申请。",
	"auth.tokenInvalid": "此链接无效或已被使用。",
	"auth.unauthorized": "您没有权限执行此操作。",

	"agent.notFound": "未找到该代理。",
	"agent.revoked": "该代理的访问权限已被撤销。",
	"agent.limitExceeded": "已达到该账户的代理数量上限。",
	"agent.permissionDenied": "代理没有执行此操作的权限。",

	"twoFactor.invalidCode": "验证码无效，请检查您的验证应用并重试。",
	"twoFactor.alreadyEnabled": "该账户已启用双重验证。",
	"twoFactor.notEnabled": "该账户未启用双重验证。",

	"email.verification.subject": "请验证您的电子邮件地址",
	"email.passwordReset.subject": "重置您的密码",
	"email.magicLink.subject": "您的登录链接",
	"email.otp.subject": "您的一次性验证码",
	"email.invitation.subject": "您已被邀请加入 {{orgName}}",
	"email.welcome.subject": "欢迎使用 {{appName}}",

	"general.serverError": "出现了一些问题，请稍后再试。",
	"general.badRequest": "无法处理该请求。",
	"general.notFound": "未找到请求的资源。",
};
