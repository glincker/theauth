import { afterEach, beforeEach, vi } from "vitest";

(
	globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

function installMockLocalStorage() {
	const store = new Map<string, string>();
	const mockStorage = {
		getItem(key: string) {
			return store.get(key) ?? null;
		},
		setItem(key: string, value: string) {
			store.set(key, value);
		},
		removeItem(key: string) {
			store.delete(key);
		},
		clear() {
			store.clear();
		},
	};

	Object.defineProperty(window, "localStorage", {
		value: mockStorage,
		configurable: true,
	});
	Object.defineProperty(globalThis, "localStorage", {
		value: mockStorage,
		configurable: true,
	});
}

beforeEach(() => {
	installMockLocalStorage();
});

afterEach(() => {
	document.body.innerHTML = "";
	window.localStorage.clear();
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});
