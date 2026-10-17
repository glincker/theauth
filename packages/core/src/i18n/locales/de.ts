import type { TranslationKeys } from "../i18n.js";

export const de: TranslationKeys = {
	"auth.invalidCredentials": "Ungültige E-Mail-Adresse oder falsches Passwort.",
	"auth.emailNotVerified": "Bitte bestätige deine E-Mail-Adresse, bevor du dich anmeldest.",
	"auth.accountLocked":
		"Dein Konto wurde gesperrt. Wende dich an den Support, um es freizuschalten.",
	"auth.rateLimited": "Zu viele Anfragen. Versuche es in {{retryAfter}} Sekunden erneut.",
	"auth.emailAlreadyExists": "Ein Konto mit dieser E-Mail-Adresse existiert bereits.",
	"auth.weakPassword":
		"Das Passwort ist zu schwach. Verwende mindestens 8 Zeichen mit Buchstaben, Zahlen und Symbolen.",
	"auth.tokenExpired": "Dieser Link ist abgelaufen. Fordere einen neuen an.",
	"auth.tokenInvalid": "Dieser Link ist ungültig oder wurde bereits verwendet.",
	"auth.unauthorized": "Du bist nicht berechtigt, diese Aktion auszuführen.",

	"agent.notFound": "Agent nicht gefunden.",
	"agent.revoked": "Der Zugriff dieses Agenten wurde widerrufen.",
	"agent.limitExceeded": "Agentenlimit für dieses Konto erreicht.",
	"agent.permissionDenied": "Der Agent hat keine Berechtigung für diese Aktion.",

	"twoFactor.invalidCode":
		"Ungültiger Bestätigungscode. Überprüfe deine Authentifizierungs-App und versuche es erneut.",
	"twoFactor.alreadyEnabled":
		"Die Zwei-Faktor-Authentifizierung ist für dieses Konto bereits aktiviert.",
	"twoFactor.notEnabled": "Die Zwei-Faktor-Authentifizierung ist für dieses Konto nicht aktiviert.",

	"email.verification.subject": "Bestätige deine E-Mail-Adresse",
	"email.passwordReset.subject": "Setze dein Passwort zurück",
	"email.magicLink.subject": "Dein Anmelde-Link",
	"email.otp.subject": "Dein Einmalcode",
	"email.invitation.subject": "Du wurdest eingeladen, {{orgName}} beizutreten",
	"email.welcome.subject": "Willkommen bei {{appName}}",

	"general.serverError": "Etwas ist schiefgelaufen. Versuche es später erneut.",
	"general.badRequest": "Die Anfrage konnte nicht verarbeitet werden.",
	"general.notFound": "Die angeforderte Ressource wurde nicht gefunden.",
};
