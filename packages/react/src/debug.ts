export function resolveDebug(propDebug?: boolean): boolean {
	if (propDebug) return true;
	if (typeof window === "undefined") return false;
	try {
		return window.localStorage.getItem("DEBUG") === "theauth";
	} catch {
		return false;
	}
}

export function makeLogger(enabled: boolean) {
	return (_event: string, _detail?: unknown): void => {
		if (!enabled) return;
	};
}
