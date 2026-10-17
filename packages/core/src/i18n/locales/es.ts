import type { TranslationKeys } from "../i18n.js";

export const es: TranslationKeys = {
	"auth.invalidCredentials": "Correo electrónico o contraseña incorrectos.",
	"auth.emailNotVerified": "Verifica tu dirección de correo electrónico antes de iniciar sesión.",
	"auth.accountLocked": "Tu cuenta ha sido bloqueada. Contacta con soporte para desbloquearla.",
	"auth.rateLimited": "Demasiadas solicitudes. Inténtalo de nuevo en {{retryAfter}} segundos.",
	"auth.emailAlreadyExists": "Ya existe una cuenta con ese correo electrónico.",
	"auth.weakPassword":
		"La contraseña es demasiado débil. Usa al menos 8 caracteres con letras, números y símbolos.",
	"auth.tokenExpired": "Este enlace ha caducado. Solicita uno nuevo.",
	"auth.tokenInvalid": "Este enlace no es válido o ya ha sido utilizado.",
	"auth.unauthorized": "No tienes autorización para realizar esta acción.",

	"agent.notFound": "Agente no encontrado.",
	"agent.revoked": "El acceso de este agente ha sido revocado.",
	"agent.limitExceeded": "Límite de agentes alcanzado para esta cuenta.",
	"agent.permissionDenied": "El agente no tiene permiso para realizar esta acción.",

	"twoFactor.invalidCode":
		"Código de verificación incorrecto. Comprueba tu aplicación autenticadora e inténtalo de nuevo.",
	"twoFactor.alreadyEnabled": "La autenticación de dos factores ya está activada en esta cuenta.",
	"twoFactor.notEnabled": "La autenticación de dos factores no está activada en esta cuenta.",

	"email.verification.subject": "Verifica tu dirección de correo electrónico",
	"email.passwordReset.subject": "Restablece tu contraseña",
	"email.magicLink.subject": "Tu enlace de acceso",
	"email.otp.subject": "Tu código de un solo uso",
	"email.invitation.subject": "Has sido invitado a unirte a {{orgName}}",
	"email.welcome.subject": "Bienvenido a {{appName}}",

	"general.serverError": "Algo salió mal. Inténtalo de nuevo más tarde.",
	"general.badRequest": "La solicitud no pudo procesarse.",
	"general.notFound": "El recurso solicitado no fue encontrado.",
};
