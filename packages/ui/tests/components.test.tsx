/**
 * Tests for @theauth/ui components.
 *
 * Covers:
 * - cx() utility: string, function, and undefined overrides
 * - AuthCard: title, description, children rendering
 * - OAuthButtons: provider buttons, grid vs list layout, empty providers
 * - SignIn: form fields, submit callback
 * - SignUp: name/email/password/confirm fields, submit callback
 * - UserButton: avatar rendering, dropdown toggle
 * - TwoFactorVerify: digit inputs, paste handling
 * - ForgotPassword: email input, success state
 */

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

// ─── Module mocks ─────────────────────────────────────────────────────────────

// Must be defined before imports that depend on @theauth/react
const mockSignIn = vi.fn();
const mockSignUp = vi.fn();
const mockSignOut = vi.fn();

vi.mock("@theauth/react", () => ({
	useSignIn: () => ({
		signIn: mockSignIn,
		isLoading: false,
		error: null,
	}),
	useSignUp: () => ({
		signUp: mockSignUp,
		isLoading: false,
		error: null,
	}),
	useUser: () => ({
		user: { id: "u1", name: "Ada Lovelace", email: "ada@example.com", image: undefined },
		isLoading: false,
		isAuthenticated: true,
	}),
	useSignOut: () => ({
		signOut: mockSignOut,
	}),
}));

// ─── Component imports (after mocks) ─────────────────────────────────────────

import { AuthCard } from "../src/components/auth-card.js";
import { ForgotPassword } from "../src/components/forgot-password.js";
import { OAuthButtons } from "../src/components/oauth-buttons.js";
import { SignIn } from "../src/components/sign-in.js";
import { SignUp } from "../src/components/sign-up.js";
import { TwoFactorVerify } from "../src/components/two-factor-verify.js";
import { UserButton } from "../src/components/user-button.js";
import { cx } from "../src/utils.js";

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getForm(submitButtonName: string): HTMLFormElement {
	const btn = screen.getByRole("button", { name: submitButtonName });
	const form = btn.closest("form");
	if (!form) throw new Error(`No form ancestor found for button "${submitButtonName}"`);
	return form;
}

// ─── cx() ─────────────────────────────────────────────────────────────────────

describe("cx()", () => {
	it("returns defaults when override is undefined", () => {
		expect(cx("base-class")).toBe("base-class");
		expect(cx("base-class", undefined)).toBe("base-class");
	});

	it("appends a string override to defaults", () => {
		expect(cx("base", "extra")).toBe("base extra");
	});

	it("calls a function override with defaults and uses its return value", () => {
		const result = cx("base", (d) => `${d} transformed`);
		expect(result).toBe("base transformed");
	});

	it("function override can completely replace defaults", () => {
		expect(cx("base", () => "replaced")).toBe("replaced");
	});
});

// ─── AuthCard ─────────────────────────────────────────────────────────────────

describe("AuthCard", () => {
	it("renders children", () => {
		render(
			<AuthCard>
				<span>child content</span>
			</AuthCard>,
		);
		expect(screen.getByText("child content")).toBeTruthy();
	});

	it("renders title when provided", () => {
		render(
			<AuthCard title="Welcome back">
				<span />
			</AuthCard>,
		);
		expect(screen.getByText("Welcome back")).toBeTruthy();
	});

	it("renders description when provided", () => {
		render(
			<AuthCard title="T" description="Subtitle text">
				<span />
			</AuthCard>,
		);
		expect(screen.getByText("Subtitle text")).toBeTruthy();
	});

	it("does not render a title element when title is omitted", () => {
		render(
			<AuthCard>
				<span>body</span>
			</AuthCard>,
		);
		expect(screen.queryByRole("heading")).toBeNull();
	});
});

// ─── OAuthButtons ─────────────────────────────────────────────────────────────

describe("OAuthButtons", () => {
	const providers = [
		{ id: "github", name: "GitHub" },
		{ id: "google", name: "Google" },
	];

	it("renders a button for each provider in list layout", () => {
		render(<OAuthButtons providers={providers} />);
		expect(screen.getByText("Continue with GitHub")).toBeTruthy();
		expect(screen.getByText("Continue with Google")).toBeTruthy();
	});

	it("renders sign-up labels when mode is signup", () => {
		render(<OAuthButtons providers={providers} mode="signup" />);
		expect(screen.getByText("Sign up with GitHub")).toBeTruthy();
	});

	it("returns null when providers array is empty", () => {
		const { container } = render(<OAuthButtons providers={[]} />);
		expect(container.firstChild).toBeNull();
	});

	it("uses grid layout class when layout is grid", () => {
		const { container } = render(<OAuthButtons providers={providers} layout="grid" />);
		const root = container.firstChild as HTMLElement;
		expect(root.className).toContain("grid");
	});

	it("uses list layout class by default", () => {
		const { container } = render(<OAuthButtons providers={providers} />);
		const root = container.firstChild as HTMLElement;
		expect(root.className).toContain("flex");
	});

	it("disables all buttons when disabled prop is true", () => {
		render(<OAuthButtons providers={providers} disabled />);
		const buttons = screen.getAllByRole("button");
		for (const btn of buttons) {
			expect((btn as HTMLButtonElement).disabled).toBe(true);
		}
	});

	it("shows the first letter of provider name as fallback icon", () => {
		render(<OAuthButtons providers={[{ id: "discord", name: "Discord" }]} />);
		expect(screen.getByText("D")).toBeTruthy();
	});
});

// ─── SignIn ───────────────────────────────────────────────────────────────────

describe("SignIn", () => {
	it("renders email and password inputs", () => {
		render(<SignIn />);
		expect(screen.getByPlaceholderText("you@example.com")).toBeTruthy();
		expect(screen.getByPlaceholderText("Enter your password")).toBeTruthy();
	});

	it("renders the title", () => {
		render(<SignIn title="Log in" />);
		expect(screen.getByText("Log in")).toBeTruthy();
	});

	it("renders the submit button", () => {
		render(<SignIn />);
		expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
	});

	it("calls onSuccess after successful sign-in", async () => {
		mockSignIn.mockResolvedValue({ success: true });
		const onSuccess = vi.fn();
		render(<SignIn onSuccess={onSuccess} />);

		await userEvent.type(screen.getByPlaceholderText("you@example.com"), "test@example.com");
		await userEvent.type(screen.getByPlaceholderText("Enter your password"), "secret123");
		fireEvent.submit(getForm("Sign in"));

		await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
	});

	it("shows forgot password link when forgotPasswordUrl is provided", () => {
		render(<SignIn forgotPasswordUrl="/forgot" />);
		expect(screen.getByText("Forgot password?")).toBeTruthy();
	});

	it("shows sign-up link when signUpUrl is provided", () => {
		render(<SignIn signUpUrl="/sign-up" />);
		expect(screen.getByText("Sign up")).toBeTruthy();
	});

	it("renders OAuth provider buttons when providers are passed", () => {
		render(<SignIn providers={[{ id: "github", name: "GitHub" }]} />);
		expect(screen.getByText("Continue with GitHub")).toBeTruthy();
	});

	it("renders magic link toggle when showMagicLink is true", () => {
		render(<SignIn showMagicLink />);
		expect(screen.getByRole("button", { name: "Magic link" })).toBeTruthy();
	});
});

// ─── SignUp ───────────────────────────────────────────────────────────────────

describe("SignUp", () => {
	it("renders name, email, password, and confirm password fields by default", () => {
		render(<SignUp />);
		expect(screen.getByPlaceholderText("Your name")).toBeTruthy();
		expect(screen.getByPlaceholderText("you@example.com")).toBeTruthy();
		expect(screen.getByPlaceholderText("At least 8 characters")).toBeTruthy();
		expect(screen.getByPlaceholderText("Repeat your password")).toBeTruthy();
	});

	it("hides name field when showName is false", () => {
		render(<SignUp showName={false} />);
		expect(screen.queryByPlaceholderText("Your name")).toBeNull();
	});

	it("hides confirm password field when confirmPassword is false", () => {
		render(<SignUp confirmPassword={false} />);
		expect(screen.queryByPlaceholderText("Repeat your password")).toBeNull();
	});

	it("renders the submit button", () => {
		render(<SignUp />);
		expect(screen.getByRole("button", { name: "Create account" })).toBeTruthy();
	});

	it("calls onSuccess after successful sign-up", async () => {
		mockSignUp.mockResolvedValue({ success: true });
		const onSuccess = vi.fn();
		render(<SignUp onSuccess={onSuccess} confirmPassword={false} showName={false} />);

		await userEvent.type(screen.getByPlaceholderText("you@example.com"), "new@example.com");
		await userEvent.type(screen.getByPlaceholderText("At least 8 characters"), "password123");
		fireEvent.submit(getForm("Create account"));

		await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
	});

	it("shows a password mismatch error without calling signUp", async () => {
		render(<SignUp />);

		await userEvent.type(screen.getByPlaceholderText("you@example.com"), "user@example.com");
		await userEvent.type(screen.getByPlaceholderText("At least 8 characters"), "password123");
		await userEvent.type(screen.getByPlaceholderText("Repeat your password"), "different123");
		fireEvent.submit(getForm("Create account"));

		await waitFor(() => expect(screen.getByText("Passwords don't match")).toBeTruthy());
		expect(mockSignUp).not.toHaveBeenCalled();
	});

	it("shows sign-in link when signInUrl is provided", () => {
		render(<SignUp signInUrl="/sign-in" />);
		expect(screen.getByText("Sign in")).toBeTruthy();
	});
});

// ─── UserButton ───────────────────────────────────────────────────────────────

describe("UserButton", () => {
	it("renders the avatar trigger button", () => {
		render(<UserButton />);
		expect(screen.getByRole("button")).toBeTruthy();
	});

	it("does not show dropdown by default", () => {
		render(<UserButton />);
		expect(screen.queryByRole("menu")).toBeNull();
	});

	it("opens dropdown when trigger is clicked", async () => {
		render(<UserButton />);
		await userEvent.click(screen.getByRole("button"));
		expect(screen.getByRole("menu")).toBeTruthy();
	});

	it("shows user name in dropdown", async () => {
		render(<UserButton />);
		await userEvent.click(screen.getByRole("button"));
		expect(screen.getByText("Ada Lovelace")).toBeTruthy();
	});

	it("shows user email in dropdown when showEmail is true", async () => {
		render(<UserButton showEmail />);
		await userEvent.click(screen.getByRole("button"));
		expect(screen.getByText("ada@example.com")).toBeTruthy();
	});

	it("hides user email when showEmail is false", async () => {
		render(<UserButton showEmail={false} />);
		await userEvent.click(screen.getByRole("button"));
		expect(screen.queryByText("ada@example.com")).toBeNull();
	});

	it("closes dropdown when escape key is pressed", async () => {
		render(<UserButton />);
		await userEvent.click(screen.getByRole("button"));
		expect(screen.getByRole("menu")).toBeTruthy();

		await userEvent.keyboard("{Escape}");
		await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
	});

	it("renders custom menu items", async () => {
		render(<UserButton menuItems={[{ label: "Settings", onClick: vi.fn() }]} />);
		await userEvent.click(screen.getByRole("button"));
		expect(screen.getByRole("menuitem", { name: "Settings" })).toBeTruthy();
	});

	it("calls onSignOut when sign out is clicked", async () => {
		const onSignOut = vi.fn();
		mockSignOut.mockResolvedValue(undefined);
		render(<UserButton onSignOut={onSignOut} />);
		await userEvent.click(screen.getByRole("button"));
		await userEvent.click(screen.getByRole("menuitem", { name: /sign out/i }));
		await waitFor(() => expect(onSignOut).toHaveBeenCalledOnce());
	});
});

// ─── TwoFactorVerify ──────────────────────────────────────────────────────────

describe("TwoFactorVerify", () => {
	it("renders 6 digit inputs by default", () => {
		render(<TwoFactorVerify />);
		const inputs = screen.getAllByRole("textbox");
		const digitInputs = inputs.filter((el) => (el as HTMLInputElement).maxLength === 1);
		expect(digitInputs).toHaveLength(6);
	});

	it("renders the correct number of digit inputs when digits prop is set", () => {
		render(<TwoFactorVerify digits={4} />);
		const inputs = screen.getAllByRole("textbox");
		const digitInputs = inputs.filter((el) => (el as HTMLInputElement).maxLength === 1);
		expect(digitInputs).toHaveLength(4);
	});

	it("renders the title", () => {
		render(<TwoFactorVerify title="Enter code" />);
		expect(screen.getByText("Enter code")).toBeTruthy();
	});

	it("renders the verify button", () => {
		render(<TwoFactorVerify />);
		expect(screen.getByRole("button", { name: "Verify" })).toBeTruthy();
	});

	it("renders a backup code toggle when showBackupOption is true", () => {
		render(<TwoFactorVerify showBackupOption />);
		expect(screen.getByText("Use backup code")).toBeTruthy();
	});

	it("switches to backup code input when toggle is clicked", async () => {
		render(<TwoFactorVerify showBackupOption />);
		await userEvent.click(screen.getByText("Use backup code"));
		expect(screen.getByPlaceholderText("Backup code")).toBeTruthy();
	});

	it("spreads pasted digits across inputs", () => {
		render(<TwoFactorVerify digits={6} />);
		const inputs = screen.getAllByRole("textbox");
		const firstDigitInput = inputs.find((el) => (el as HTMLInputElement).maxLength === 1);
		if (!firstDigitInput) throw new Error("No digit input found");

		fireEvent.paste(firstDigitInput, {
			clipboardData: { getData: () => "123456" },
		});

		const digitInputs = screen
			.getAllByRole("textbox")
			.filter((el) => (el as HTMLInputElement).maxLength === 1);
		const values = digitInputs.map((el) => (el as HTMLInputElement).value);
		expect(values).toEqual(["1", "2", "3", "4", "5", "6"]);
	});

	it("renders a cancel button when onCancel is provided", () => {
		render(<TwoFactorVerify onCancel={vi.fn()} />);
		expect(screen.getByRole("button", { name: "Cancel" })).toBeTruthy();
	});

	it("calls onCancel when cancel button is clicked", async () => {
		const onCancel = vi.fn();
		render(<TwoFactorVerify onCancel={onCancel} />);
		await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
		expect(onCancel).toHaveBeenCalledOnce();
	});
});

// ─── ForgotPassword ───────────────────────────────────────────────────────────

describe("ForgotPassword", () => {
	it("renders the email input", () => {
		render(<ForgotPassword />);
		expect(screen.getByPlaceholderText("you@example.com")).toBeTruthy();
	});

	it("renders the submit button", () => {
		render(<ForgotPassword />);
		expect(screen.getByRole("button", { name: "Send reset link" })).toBeTruthy();
	});

	it("renders the title", () => {
		render(<ForgotPassword title="Forgot your password?" />);
		expect(screen.getByText("Forgot your password?")).toBeTruthy();
	});

	it("shows success state after form submission", async () => {
		global.fetch = vi.fn().mockResolvedValue({ ok: true }) as typeof fetch;

		render(<ForgotPassword />);
		await userEvent.type(screen.getByPlaceholderText("you@example.com"), "reset@example.com");
		fireEvent.submit(getForm("Send reset link"));

		await waitFor(() => expect(screen.getByText("Check your email")).toBeTruthy());
	});

	it("shows sign-in link when signInUrl is provided", () => {
		render(<ForgotPassword signInUrl="/sign-in" />);
		expect(screen.getByText("Sign in")).toBeTruthy();
	});

	it("allows retrying after success state", async () => {
		global.fetch = vi.fn().mockResolvedValue({ ok: true }) as typeof fetch;

		render(<ForgotPassword />);
		await userEvent.type(screen.getByPlaceholderText("you@example.com"), "reset@example.com");
		fireEvent.submit(getForm("Send reset link"));

		await waitFor(() => screen.getByText("Try again"));
		await userEvent.click(screen.getByText("Try again"));

		expect(screen.getByPlaceholderText("you@example.com")).toBeTruthy();
	});

	it("calls onSuccess after form submission", async () => {
		global.fetch = vi.fn().mockResolvedValue({ ok: true }) as typeof fetch;
		const onSuccess = vi.fn();

		render(<ForgotPassword onSuccess={onSuccess} />);
		await userEvent.type(screen.getByPlaceholderText("you@example.com"), "reset@example.com");
		fireEvent.submit(getForm("Send reset link"));

		await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
	});
});
