import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ElectronApi, IpcMainListener } from "../src/electron-api.js";
import { setElectronApiForTesting } from "../src/electron-api.js";
import type { SecureStorage } from "../src/storage.js";
import { createMemoryStorage } from "../src/storage.js";

// ─── fs/path mocks ────────────────────────────────────────────────────────────

const mockFs: Record<string, string> = {};

vi.mock("node:fs", () => ({
	readFileSync: vi.fn((filePath: string): string => {
		const content = mockFs[filePath];
		if (content === undefined) throw new Error(`ENOENT: ${filePath}`);
		return content;
	}),
	writeFileSync: vi.fn((filePath: string, data: string): void => {
		mockFs[filePath] = data;
	}),
	mkdirSync: vi.fn(),
}));

vi.mock("node:path", () => ({
	join: vi.fn((...parts: string[]) => parts.join("/")),
	dirname: vi.fn((p: string) => p.split("/").slice(0, -1).join("/")),
}));

// ─── Electron mock factory ────────────────────────────────────────────────────

function makeMockSafeStorage(available = true) {
	return {
		available,
		isEncryptionAvailable: vi.fn(function (this: { available: boolean }) {
			return this.available;
		}),
		encryptString: vi.fn((value: string): Uint8Array => {
			const encoder = new TextEncoder();
			// Reversible XOR with 0x42 for tests
			return encoder.encode(value).map((b) => b ^ 0x42);
		}),
		decryptString: vi.fn((encrypted: Uint8Array): string => {
			const decoder = new TextDecoder();
			return decoder.decode(encrypted.map((b) => b ^ 0x42));
		}),
	};
}

function makeMockIpcMain() {
	return {
		handle: vi.fn<[string, IpcMainListener], void>(),
		removeHandler: vi.fn<[string], void>(),
	};
}

function makeMockIpcRenderer() {
	return {
		invoke: vi.fn<[string, ...unknown[]], Promise<unknown>>(),
	};
}

function makeElectronApi(overrides: Partial<ElectronApi> = {}): ElectronApi {
	const safeStorage = makeMockSafeStorage();
	return {
		safeStorage: {
			isEncryptionAvailable: safeStorage.isEncryptionAvailable.bind(safeStorage),
			encryptString: safeStorage.encryptString,
			decryptString: safeStorage.decryptString,
		},
		app: {
			getPath: vi.fn(() => "/tmp/theauth-test"),
		},
		BrowserWindow: vi.fn() as unknown as ElectronApi["BrowserWindow"],
		ipcMain: makeMockIpcMain(),
		ipcRenderer: makeMockIpcRenderer(),
		...overrides,
	};
}

// ─── Memory storage tests ─────────────────────────────────────────────────────

describe("createMemoryStorage", () => {
	it("returns null for unknown keys", async () => {
		const storage = createMemoryStorage();
		expect(await storage.get("missing")).toBeNull();
	});

	it("stores and retrieves a value", async () => {
		const storage = createMemoryStorage();
		await storage.set("key", "value");
		expect(await storage.get("key")).toBe("value");
	});

	it("overwrites an existing value", async () => {
		const storage = createMemoryStorage();
		await storage.set("key", "first");
		await storage.set("key", "second");
		expect(await storage.get("key")).toBe("second");
	});

	it("removes a key", async () => {
		const storage = createMemoryStorage();
		await storage.set("key", "value");
		await storage.remove("key");
		expect(await storage.get("key")).toBeNull();
	});

	it("remove on non-existent key is a no-op", async () => {
		const storage = createMemoryStorage();
		await expect(storage.remove("ghost")).resolves.toBeUndefined();
	});

	it("clears all keys", async () => {
		const storage = createMemoryStorage();
		await storage.set("a", "1");
		await storage.set("b", "2");
		await storage.clear();
		expect(await storage.get("a")).toBeNull();
		expect(await storage.get("b")).toBeNull();
	});

	it("clear on empty storage is a no-op", async () => {
		const storage = createMemoryStorage();
		await expect(storage.clear()).resolves.toBeUndefined();
	});

	it("isolates data between instances", async () => {
		const s1 = createMemoryStorage();
		const s2 = createMemoryStorage();
		await s1.set("key", "from-s1");
		expect(await s2.get("key")).toBeNull();
	});
});

// ─── ElectronStorage: encryption available ────────────────────────────────────

describe("createElectronStorage (encryption available)", () => {
	let storage: SecureStorage;
	let encryptSpy: ReturnType<typeof vi.fn>;
	let decryptSpy: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		for (const k of Object.keys(mockFs)) {
			Reflect.deleteProperty(mockFs, k);
		}

		const safeStorage = makeMockSafeStorage(true);
		encryptSpy = safeStorage.encryptString;
		decryptSpy = safeStorage.decryptString;

		setElectronApiForTesting(
			makeElectronApi({
				safeStorage: {
					isEncryptionAvailable: safeStorage.isEncryptionAvailable.bind(safeStorage),
					encryptString: safeStorage.encryptString,
					decryptString: safeStorage.decryptString,
				},
			}),
		);

		const { createElectronStorage } = await import("../src/storage.js");
		storage = createElectronStorage({ fileName: "test-session.json" });
	});

	afterEach(() => {
		setElectronApiForTesting(null);
	});

	it("encrypts values before writing to disk", async () => {
		await storage.set("token", "secret-value");
		expect(encryptSpy).toHaveBeenCalledWith("secret-value");
	});

	it("decrypts values when reading from disk", async () => {
		await storage.set("token", "secret-value");
		const retrieved = await storage.get("token");
		expect(retrieved).toBe("secret-value");
		expect(decryptSpy).toHaveBeenCalled();
	});

	it("returns null for missing keys", async () => {
		expect(await storage.get("nonexistent")).toBeNull();
	});

	it("removes a key from disk", async () => {
		await storage.set("k", "v");
		await storage.remove("k");
		expect(await storage.get("k")).toBeNull();
	});

	it("clears all keys from disk", async () => {
		await storage.set("a", "1");
		await storage.set("b", "2");
		await storage.clear();
		expect(await storage.get("a")).toBeNull();
		expect(await storage.get("b")).toBeNull();
	});

	it("writes a JSON file to the userData directory", async () => {
		await storage.set("x", "y");
		const writtenPaths = Object.keys(mockFs);
		expect(writtenPaths.some((p) => p.includes("test-session.json"))).toBe(true);
	});
});

// ─── ElectronStorage: encryption unavailable (fallback) ───────────────────────

describe("createElectronStorage (encryption unavailable)", () => {
	let storage: SecureStorage;
	let warnSpy: ReturnType<typeof vi.spyOn>;
	let encryptSpy: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		for (const k of Object.keys(mockFs)) {
			Reflect.deleteProperty(mockFs, k);
		}

		const safeStorage = makeMockSafeStorage(false);
		encryptSpy = safeStorage.encryptString;
		warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);

		setElectronApiForTesting(
			makeElectronApi({
				safeStorage: {
					isEncryptionAvailable: safeStorage.isEncryptionAvailable.bind(safeStorage),
					encryptString: safeStorage.encryptString,
					decryptString: safeStorage.decryptString,
				},
			}),
		);

		const { createElectronStorage } = await import("../src/storage.js");
		storage = createElectronStorage({ fileName: "fallback-session.json" });
	});

	afterEach(() => {
		setElectronApiForTesting(null);
		warnSpy.mockRestore();
	});

	it("emits a warning when encryption is unavailable", async () => {
		await storage.set("key", "value");
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("safeStorage encryption unavailable"),
		);
	});

	it("stores values as plaintext when encryption is unavailable", async () => {
		await storage.set("key", "plaintext-value");
		expect(encryptSpy).not.toHaveBeenCalled();
	});

	it("retrieves plaintext values correctly", async () => {
		await storage.set("key", "plaintext-value");
		const val = await storage.get("key");
		expect(val).toBe("plaintext-value");
	});

	it("emits the warning only once across multiple operations", async () => {
		await storage.set("k1", "v1");
		await storage.set("k2", "v2");
		await storage.get("k1");
		expect(warnSpy).toHaveBeenCalledTimes(1);
	});
});

// ─── OAuth window ─────────────────────────────────────────────────────────────

describe("openOAuthWindow", () => {
	afterEach(() => {
		setElectronApiForTesting(null);
	});

	it("constructs the auth URL with the provider ID and basePath", async () => {
		let capturedUrl = "";
		let closedCb: (() => void) | null = null;

		const mockWin = {
			loadURL: vi.fn(async (url: string) => {
				capturedUrl = url;
			}),
			on: vi.fn((event: string, cb: () => void) => {
				if (event === "closed") closedCb = cb;
			}),
			webContents: {
				on: vi.fn(),
				session: { cookies: { get: vi.fn(async () => []) } },
			},
			destroy: vi.fn(),
			show: vi.fn(),
		};

		const MockBrowserWindow = vi.fn(() => mockWin);
		setElectronApiForTesting(
			makeElectronApi({
				BrowserWindow: MockBrowserWindow as unknown as ElectronApi["BrowserWindow"],
			}),
		);

		const { openOAuthWindow } = await import("../src/oauth-window.js");

		setTimeout(() => closedCb?.(), 20);

		const result = await openOAuthWindow("github", { basePath: "/api/theauth" });

		expect(capturedUrl).toContain("/api/theauth/sign-in/github");
		expect(capturedUrl).toContain("redirect=electron");
		expect(result.success).toBe(false);
		expect(result.error).toBe("Window closed by user");
	});

	it("uses default width=500 and height=700", async () => {
		let capturedOptions: Record<string, unknown> = {};
		let closedCb: (() => void) | null = null;

		const mockWin = {
			loadURL: vi.fn(async () => undefined),
			on: vi.fn((event: string, cb: () => void) => {
				if (event === "closed") closedCb = cb;
			}),
			webContents: {
				on: vi.fn(),
				session: { cookies: { get: vi.fn(async () => []) } },
			},
			destroy: vi.fn(),
			show: vi.fn(),
		};

		const MockBrowserWindow = vi.fn((opts: unknown) => {
			capturedOptions = opts as Record<string, unknown>;
			return mockWin;
		});
		setElectronApiForTesting(
			makeElectronApi({
				BrowserWindow: MockBrowserWindow as unknown as ElectronApi["BrowserWindow"],
			}),
		);

		const { openOAuthWindow } = await import("../src/oauth-window.js");
		setTimeout(() => closedCb?.(), 20);

		await openOAuthWindow("google");

		expect(capturedOptions.width).toBe(500);
		expect(capturedOptions.height).toBe(700);
	});

	it("URL-encodes the provider ID", async () => {
		let capturedUrl = "";
		let closedCb: (() => void) | null = null;

		const mockWin = {
			loadURL: vi.fn(async (url: string) => {
				capturedUrl = url;
			}),
			on: vi.fn((event: string, cb: () => void) => {
				if (event === "closed") closedCb = cb;
			}),
			webContents: {
				on: vi.fn(),
				session: { cookies: { get: vi.fn(async () => []) } },
			},
			destroy: vi.fn(),
			show: vi.fn(),
		};

		const MockBrowserWindow = vi.fn(() => mockWin);
		setElectronApiForTesting(
			makeElectronApi({
				BrowserWindow: MockBrowserWindow as unknown as ElectronApi["BrowserWindow"],
			}),
		);

		const { openOAuthWindow } = await import("../src/oauth-window.js");
		setTimeout(() => closedCb?.(), 20);

		await openOAuthWindow("my provider");
		expect(capturedUrl).toContain("my%20provider");
	});

	it("resolves success=false with error message on OAuth error in callback URL", async () => {
		let closedCb: (() => void) | null = null;
		let navigateCb: ((_ev: unknown, url: string) => void) | null = null;

		const mockWin = {
			loadURL: vi.fn(async () => undefined),
			on: vi.fn((event: string, cb: () => void) => {
				if (event === "closed") closedCb = cb;
			}),
			webContents: {
				on: vi.fn((event: string, cb: (_ev: unknown, url: string) => void) => {
					if (event === "will-redirect") navigateCb = cb;
				}),
				session: { cookies: { get: vi.fn(async () => []) } },
			},
			destroy: vi.fn(),
			show: vi.fn(),
		};

		const MockBrowserWindow = vi.fn(() => mockWin);
		setElectronApiForTesting(
			makeElectronApi({
				BrowserWindow: MockBrowserWindow as unknown as ElectronApi["BrowserWindow"],
			}),
		);

		const { openOAuthWindow } = await import("../src/oauth-window.js");

		const resultPromise = openOAuthWindow("github", { basePath: "/api/theauth" });

		await Promise.resolve();
		navigateCb?.(
			{},
			"/api/theauth/callback?error=access_denied&error_description=User+denied+access",
		);

		const result = await resultPromise;
		expect(result.success).toBe(false);
		expect(result.error).toBe("User denied access");

		void closedCb;
	});
});

// ─── setupTheAuthIpc ───────────────────────────────────────────────────────────

describe("setupTheAuthIpc", () => {
	let mockIpcMain: ReturnType<typeof makeMockIpcMain>;

	beforeEach(() => {
		mockIpcMain = makeMockIpcMain();
		setElectronApiForTesting(makeElectronApi({ ipcMain: mockIpcMain }));
	});

	afterEach(() => {
		setElectronApiForTesting(null);
	});

	it("registers handlers for all four storage channels", async () => {
		const { setupTheAuthIpc, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		const storage = createMemoryStorage();
		setupTheAuthIpc(storage);

		const registeredChannels = mockIpcMain.handle.mock.calls.map(([ch]) => ch);
		expect(registeredChannels).toContain(THEAUTH_IPC_CHANNELS.GET);
		expect(registeredChannels).toContain(THEAUTH_IPC_CHANNELS.SET);
		expect(registeredChannels).toContain(THEAUTH_IPC_CHANNELS.REMOVE);
		expect(registeredChannels).toContain(THEAUTH_IPC_CHANNELS.CLEAR);
	});

	it("removes existing handlers before re-registering", async () => {
		const { setupTheAuthIpc, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		const storage = createMemoryStorage();
		setupTheAuthIpc(storage);

		const removedChannels = mockIpcMain.removeHandler.mock.calls.map(([ch]) => ch);
		expect(removedChannels).toContain(THEAUTH_IPC_CHANNELS.GET);
		expect(removedChannels).toContain(THEAUTH_IPC_CHANNELS.SET);
		expect(removedChannels).toContain(THEAUTH_IPC_CHANNELS.REMOVE);
		expect(removedChannels).toContain(THEAUTH_IPC_CHANNELS.CLEAR);
	});

	it("GET handler returns stored value", async () => {
		const { setupTheAuthIpc, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		const storage = createMemoryStorage();
		await storage.set("mykey", "myvalue");

		setupTheAuthIpc(storage);

		const getCall = mockIpcMain.handle.mock.calls.find(([ch]) => ch === THEAUTH_IPC_CHANNELS.GET);
		expect(getCall).toBeDefined();

		const handler = getCall![1];
		const mockEvent = { reply: vi.fn() };
		const result = await handler(mockEvent, { key: "mykey" });
		expect(result).toEqual({ value: "myvalue" });
	});

	it("GET handler returns null for missing key", async () => {
		const { setupTheAuthIpc, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		const storage = createMemoryStorage();
		setupTheAuthIpc(storage);

		const getCall = mockIpcMain.handle.mock.calls.find(([ch]) => ch === THEAUTH_IPC_CHANNELS.GET);
		const handler = getCall![1];
		const result = await handler({ reply: vi.fn() }, { key: "nope" });
		expect(result).toEqual({ value: null });
	});

	it("SET handler stores a value", async () => {
		const { setupTheAuthIpc, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		const storage = createMemoryStorage();
		setupTheAuthIpc(storage);

		const setCall = mockIpcMain.handle.mock.calls.find(([ch]) => ch === THEAUTH_IPC_CHANNELS.SET);
		const handler = setCall![1];
		await handler({ reply: vi.fn() }, { key: "ipc-key", value: "ipc-val" });

		expect(await storage.get("ipc-key")).toBe("ipc-val");
	});

	it("REMOVE handler deletes a value", async () => {
		const { setupTheAuthIpc, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		const storage = createMemoryStorage();
		await storage.set("del-key", "del-val");
		setupTheAuthIpc(storage);

		const removeCall = mockIpcMain.handle.mock.calls.find(
			([ch]) => ch === THEAUTH_IPC_CHANNELS.REMOVE,
		);
		const handler = removeCall![1];
		await handler({ reply: vi.fn() }, { key: "del-key" });

		expect(await storage.get("del-key")).toBeNull();
	});

	it("CLEAR handler empties storage", async () => {
		const { setupTheAuthIpc, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		const storage = createMemoryStorage();
		await storage.set("c1", "v1");
		await storage.set("c2", "v2");
		setupTheAuthIpc(storage);

		const clearCall = mockIpcMain.handle.mock.calls.find(
			([ch]) => ch === THEAUTH_IPC_CHANNELS.CLEAR,
		);
		const handler = clearCall![1];
		await handler({ reply: vi.fn() });

		expect(await storage.get("c1")).toBeNull();
		expect(await storage.get("c2")).toBeNull();
	});
});

// ─── createIpcStorage (renderer-side) ────────────────────────────────────────

describe("createIpcStorage", () => {
	let mockIpcRenderer: ReturnType<typeof makeMockIpcRenderer>;

	beforeEach(() => {
		mockIpcRenderer = makeMockIpcRenderer();
		setElectronApiForTesting(makeElectronApi({ ipcRenderer: mockIpcRenderer }));
	});

	afterEach(() => {
		setElectronApiForTesting(null);
	});

	it("invokes GET channel and returns value", async () => {
		const { createIpcStorage, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		mockIpcRenderer.invoke.mockResolvedValueOnce({ value: "stored-val" });

		const storage = createIpcStorage();
		const result = await storage.get("my-key");

		expect(mockIpcRenderer.invoke).toHaveBeenCalledWith(THEAUTH_IPC_CHANNELS.GET, {
			key: "my-key",
		});
		expect(result).toBe("stored-val");
	});

	it("invokes SET channel with key and value", async () => {
		const { createIpcStorage, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		mockIpcRenderer.invoke.mockResolvedValueOnce(undefined);

		const storage = createIpcStorage();
		await storage.set("token", "abc123");

		expect(mockIpcRenderer.invoke).toHaveBeenCalledWith(THEAUTH_IPC_CHANNELS.SET, {
			key: "token",
			value: "abc123",
		});
	});

	it("invokes REMOVE channel with key", async () => {
		const { createIpcStorage, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		mockIpcRenderer.invoke.mockResolvedValueOnce(undefined);

		const storage = createIpcStorage();
		await storage.remove("old-key");

		expect(mockIpcRenderer.invoke).toHaveBeenCalledWith(THEAUTH_IPC_CHANNELS.REMOVE, {
			key: "old-key",
		});
	});

	it("invokes CLEAR channel", async () => {
		const { createIpcStorage, THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		mockIpcRenderer.invoke.mockResolvedValueOnce(undefined);

		const storage = createIpcStorage();
		await storage.clear();

		expect(mockIpcRenderer.invoke).toHaveBeenCalledWith(THEAUTH_IPC_CHANNELS.CLEAR);
	});

	it("returns null when GET response has null value", async () => {
		const { createIpcStorage } = await import("../src/ipc.js");
		mockIpcRenderer.invoke.mockResolvedValueOnce({ value: null });

		const storage = createIpcStorage();
		const result = await storage.get("absent");

		expect(result).toBeNull();
	});
});

// ─── THEAUTH_IPC_CHANNELS constant ─────────────────────────────────────────────

describe("THEAUTH_IPC_CHANNELS", () => {
	it("exposes all four channel names", async () => {
		const { THEAUTH_IPC_CHANNELS } = await import("../src/ipc.js");
		expect(THEAUTH_IPC_CHANNELS.GET).toBe("theauth:storage:get");
		expect(THEAUTH_IPC_CHANNELS.SET).toBe("theauth:storage:set");
		expect(THEAUTH_IPC_CHANNELS.REMOVE).toBe("theauth:storage:remove");
		expect(THEAUTH_IPC_CHANNELS.CLEAR).toBe("theauth:storage:clear");
	});
});
