export const authKeys = {
	all: ["theauth"] as const,
	session: () => [...authKeys.all, "session"] as const,
	passkeys: () => [...authKeys.all, "passkeys"] as const,
	totp: () => [...authKeys.all, "totp"] as const,
};
