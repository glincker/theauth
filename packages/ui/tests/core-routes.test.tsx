import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@glinr/theauth-react", () => ({
	useSignIn: () => ({ signIn: vi.fn(), isLoading: false, error: null }),
	useSignUp: () => ({ signUp: vi.fn(), isLoading: false, error: null }),
	useUser: () => ({ user: null, isLoading: false, isAuthenticated: false }),
	useSignOut: () => ({ signOut: vi.fn() }),
}));

import { OAuthButtons } from "../src/components/oauth-buttons.js";
import { TwoFactorVerify } from "../src/components/two-factor-verify.js";

afterEach(cleanup);

describe("routes the core serves", () => {
	it("OAuthButtons navigates to /auth/oauth/authorize/:provider", async () => {
		const loc = { origin: "https://app.test", href: "" };
		vi.stubGlobal("location", loc);
		render(<OAuthButtons providers={[{ id: "github", name: "GitHub" }]} />);
		await userEvent.click(screen.getByText("Continue with GitHub"));
		expect(loc.href).toBe("/api/theauth/auth/oauth/authorize/github");
		vi.unstubAllGlobals();
	});

	it("TwoFactorVerify posts { code } to /auth/2fa/verify", async () => {
		const fetchMock = vi.fn().mockResolvedValue({ ok: true });
		global.fetch = fetchMock as unknown as typeof fetch;
		const onSuccess = vi.fn();
		render(<TwoFactorVerify digits={4} onSuccess={onSuccess} />);
		const first = screen.getByLabelText("Digit 1 of 4");
		fireEvent.paste(first, { clipboardData: { getData: () => "1234" } });
		fireEvent.submit(first.closest("form") as HTMLFormElement);
		await waitFor(() => expect(onSuccess).toHaveBeenCalled());
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("/api/theauth/auth/2fa/verify");
		expect(JSON.parse(String(init.body))).toEqual({ code: "1234" });
	});

	it("TwoFactorVerify shows a string error from the core", async () => {
		global.fetch = vi.fn().mockResolvedValue({
			ok: false,
			json: async () => ({ error: "Invalid TOTP code" }),
		}) as unknown as typeof fetch;
		render(<TwoFactorVerify digits={4} />);
		const first = screen.getByLabelText("Digit 1 of 4");
		fireEvent.paste(first, { clipboardData: { getData: () => "1234" } });
		fireEvent.submit(first.closest("form") as HTMLFormElement);
		await waitFor(() => expect(screen.getByText("Invalid TOTP code")).toBeTruthy());
	});
});
