/** What the login page needs to know when the authorize request asks for a stronger or fresher sign-in. */
export interface LoginRedirectDetails {
	loginPage?: string;
	returnTo?: string;
	/** Space separated `acr_values` the sign-in must reach. */
	acrValues?: string;
	/** The sign-in must be at most this many seconds old. */
	maxAge?: number;
	/** Set to `login` when the user must authenticate again whatever their session says (OpenID Connect Core). */
	prompt?: string;
}

/**
 * The URL of the login page for a `LOGIN_REQUIRED` result, or null when no login page is configured.
 * A step-up request passes `acr_values`, `max_age` and `prompt` on, so the page can ask for a passkey
 * or a TOTP code and send the user back to `returnTo` once `session.auth` meets the requirement.
 */
export function loginRedirectUrl(details: LoginRedirectDetails | undefined): string | null {
	if (!details?.loginPage) return null;
	const url = new URL(details.loginPage);
	if (details.returnTo) url.searchParams.set("returnTo", details.returnTo);
	if (details.acrValues) url.searchParams.set("acr_values", details.acrValues);
	if (details.maxAge !== undefined) url.searchParams.set("max_age", String(details.maxAge));
	if (details.prompt) url.searchParams.set("prompt", details.prompt);
	return url.toString();
}
