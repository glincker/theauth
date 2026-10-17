import type { TranslationKeys } from "../i18n.js";

export const fr: TranslationKeys = {
	"auth.invalidCredentials": "Adresse e-mail ou mot de passe incorrect.",
	"auth.emailNotVerified": "Veuillez vérifier votre adresse e-mail avant de vous connecter.",
	"auth.accountLocked":
		"Votre compte a été verrouillé. Contactez le support pour le déverrouiller.",
	"auth.rateLimited": "Trop de tentatives. Réessayez dans {{retryAfter}} secondes.",
	"auth.emailAlreadyExists": "Un compte avec cette adresse e-mail existe déjà.",
	"auth.weakPassword":
		"Le mot de passe est trop faible. Utilisez au moins 8 caractères avec des lettres, des chiffres et des symboles.",
	"auth.tokenExpired": "Ce lien a expiré. Demandez-en un nouveau.",
	"auth.tokenInvalid": "Ce lien est invalide ou a déjà été utilisé.",
	"auth.unauthorized": "Vous n'êtes pas autorisé à effectuer cette action.",

	"agent.notFound": "Agent introuvable.",
	"agent.revoked": "L'accès de cet agent a été révoqué.",
	"agent.limitExceeded": "Limite d'agents atteinte pour ce compte.",
	"agent.permissionDenied": "L'agent n'est pas autorisé à effectuer cette action.",

	"twoFactor.invalidCode":
		"Code de vérification invalide. Vérifiez votre application d'authentification et réessayez.",
	"twoFactor.alreadyEnabled": "L'authentification à deux facteurs est déjà activée sur ce compte.",
	"twoFactor.notEnabled": "L'authentification à deux facteurs n'est pas activée sur ce compte.",

	"email.verification.subject": "Vérifiez votre adresse e-mail",
	"email.passwordReset.subject": "Réinitialisez votre mot de passe",
	"email.magicLink.subject": "Votre lien de connexion",
	"email.otp.subject": "Votre code à usage unique",
	"email.invitation.subject": "Vous avez été invité à rejoindre {{orgName}}",
	"email.welcome.subject": "Bienvenue sur {{appName}}",

	"general.serverError": "Une erreur s'est produite. Réessayez plus tard.",
	"general.badRequest": "La requête n'a pas pu être traitée.",
	"general.notFound": "La ressource demandée est introuvable.",
};
