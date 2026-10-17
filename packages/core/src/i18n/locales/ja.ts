import type { TranslationKeys } from "../i18n.js";

export const ja: TranslationKeys = {
	"auth.invalidCredentials": "メールアドレスまたはパスワードが正しくありません。",
	"auth.emailNotVerified": "サインインする前にメールアドレスを確認してください。",
	"auth.accountLocked":
		"アカウントがロックされています。サポートに連絡してロックを解除してください。",
	"auth.rateLimited": "リクエストが多すぎます。{{retryAfter}}秒後に再試行してください。",
	"auth.emailAlreadyExists": "そのメールアドレスのアカウントはすでに存在します。",
	"auth.weakPassword":
		"パスワードが弱すぎます。文字、数字、記号を組み合わせた8文字以上のパスワードを使用してください。",
	"auth.tokenExpired": "このリンクの有効期限が切れています。新しいリンクをリクエストしてください。",
	"auth.tokenInvalid": "このリンクは無効か、すでに使用されています。",
	"auth.unauthorized": "この操作を実行する権限がありません。",

	"agent.notFound": "エージェントが見つかりません。",
	"agent.revoked": "このエージェントのアクセスが取り消されました。",
	"agent.limitExceeded": "このアカウントのエージェント上限に達しました。",
	"agent.permissionDenied": "エージェントにはこの操作を実行する権限がありません。",

	"twoFactor.invalidCode": "確認コードが正しくありません。認証アプリを確認して再試行してください。",
	"twoFactor.alreadyEnabled": "このアカウントでは二要素認証がすでに有効になっています。",
	"twoFactor.notEnabled": "このアカウントでは二要素認証が有効になっていません。",

	"email.verification.subject": "メールアドレスを確認してください",
	"email.passwordReset.subject": "パスワードをリセット",
	"email.magicLink.subject": "サインインリンク",
	"email.otp.subject": "ワンタイムコード",
	"email.invitation.subject": "{{orgName}}への招待",
	"email.welcome.subject": "{{appName}}へようこそ",

	"general.serverError": "問題が発生しました。後でもう一度お試しください。",
	"general.badRequest": "リクエストを処理できませんでした。",
	"general.notFound": "リクエストされたリソースが見つかりません。",
};
