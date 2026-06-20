import { describe, expect, it } from "vitest";
import type { EmailTemplateName } from "../src/email/templates.js";
import { createEmailTemplates } from "../src/email/templates.js";

describe("email templates: each template returns subject, text, html", () => {
	const templates = createEmailTemplates();

	it("verification template", () => {
		const result = templates.render("verification", {
			email: "alice@example.com",
			token: "tok123",
			verifyUrl: "https://example.com/verify?token=tok123",
		});

		expect(result.subject).toBeTruthy();
		expect(result.text).toBeTruthy();
		expect(result.html).toBeTruthy();
	});

	it("passwordReset template", () => {
		const result = templates.render("passwordReset", {
			email: "alice@example.com",
			token: "rst456",
			resetUrl: "https://example.com/reset?token=rst456",
		});

		expect(result.subject).toBeTruthy();
		expect(result.text).toBeTruthy();
		expect(result.html).toBeTruthy();
	});

	it("magicLink template", () => {
		const result = templates.render("magicLink", {
			email: "alice@example.com",
			url: "https://example.com/auth/magic?token=ml789",
		});

		expect(result.subject).toBeTruthy();
		expect(result.text).toBeTruthy();
		expect(result.html).toBeTruthy();
	});

	it("emailOtp template", () => {
		const result = templates.render("emailOtp", {
			email: "alice@example.com",
			code: "847291",
		});

		expect(result.subject).toBeTruthy();
		expect(result.text).toBeTruthy();
		expect(result.html).toBeTruthy();
	});

	it("invitation template", () => {
		const result = templates.render("invitation", {
			email: "bob@example.com",
			orgName: "Acme Corp",
			inviteUrl: "https://example.com/invites/abc",
		});

		expect(result.subject).toBeTruthy();
		expect(result.text).toBeTruthy();
		expect(result.html).toBeTruthy();
	});

	it("welcome template", () => {
		const result = templates.render("welcome", {
			email: "alice@example.com",
			name: "Alice",
		});

		expect(result.subject).toBeTruthy();
		expect(result.text).toBeTruthy();
		expect(result.html).toBeTruthy();
	});
});

describe("email templates: custom appName appears in output", () => {
	it("uses the custom appName in the subject line", () => {
		const templates = createEmailTemplates({ appName: "MyApp" });

		const magic = templates.render("magicLink", {
			email: "user@example.com",
			url: "https://myapp.com/magic",
		});
		expect(magic.subject).toContain("MyApp");

		const welcome = templates.render("welcome", {
			email: "user@example.com",
			name: "User",
		});
		expect(welcome.subject).toContain("MyApp");

		const verification = templates.render("verification", {
			email: "user@example.com",
			verifyUrl: "https://myapp.com/verify",
		});
		expect(verification.subject).toContain("MyApp");
	});

	it("uses the custom appName in the HTML header", () => {
		const templates = createEmailTemplates({ appName: "SpecialApp" });

		const result = templates.render("emailOtp", {
			email: "user@example.com",
			code: "123456",
		});
		expect(result.html).toContain("SpecialApp");
	});
});

describe("email templates: custom template override", () => {
	it("uses the custom template function when provided", () => {
		const templates = createEmailTemplates({
			appName: "MyApp",
			templates: {
				welcome: (vars) => ({
					subject: `Custom welcome for ${vars.name ?? ""}`,
					text: `Hello ${vars.name ?? ""}! Custom text.`,
					html: `<p>Hello ${vars.name ?? ""}!</p>`,
				}),
			},
		});

		const result = templates.render("welcome", { name: "Bob", email: "bob@example.com" });
		expect(result.subject).toBe("Custom welcome for Bob");
		expect(result.text).toBe("Hello Bob! Custom text.");
		expect(result.html).toBe("<p>Hello Bob!</p>");
	});

	it("still uses built-in template for non-overridden names", () => {
		const templates = createEmailTemplates({
			appName: "MyApp",
			templates: {
				welcome: () => ({
					subject: "Custom",
					text: "Custom",
					html: "<p>Custom</p>",
				}),
			},
		});

		// emailOtp was not overridden — should use built-in
		const result = templates.render("emailOtp", {
			email: "user@example.com",
			code: "999888",
		});
		expect(result.subject).toContain("999888");
	});
});

describe("email templates: HTML contains variable values", () => {
	it("verification HTML contains the verifyUrl", () => {
		const templates = createEmailTemplates();
		const result = templates.render("verification", {
			email: "alice@example.com",
			verifyUrl: "https://example.com/verify?token=abc",
		});
		expect(result.html).toContain("https://example.com/verify?token=abc");
	});

	it("passwordReset HTML contains the resetUrl", () => {
		const templates = createEmailTemplates();
		const result = templates.render("passwordReset", {
			email: "alice@example.com",
			resetUrl: "https://example.com/reset?token=xyz",
		});
		expect(result.html).toContain("https://example.com/reset?token=xyz");
	});

	it("magicLink HTML contains the url", () => {
		const templates = createEmailTemplates();
		const result = templates.render("magicLink", {
			email: "alice@example.com",
			url: "https://example.com/magic?token=ml1",
		});
		expect(result.html).toContain("https://example.com/magic?token=ml1");
	});

	it("emailOtp HTML contains the code", () => {
		const templates = createEmailTemplates();
		const result = templates.render("emailOtp", {
			email: "alice@example.com",
			code: "739201",
		});
		expect(result.html).toContain("739201");
	});

	it("invitation HTML contains the orgName and inviteUrl", () => {
		const templates = createEmailTemplates();
		const result = templates.render("invitation", {
			email: "alice@example.com",
			orgName: "Widgets Inc",
			inviteUrl: "https://example.com/invites/wid",
		});
		expect(result.html).toContain("Widgets Inc");
		expect(result.html).toContain("https://example.com/invites/wid");
	});

	it("welcome HTML contains the user name", () => {
		const templates = createEmailTemplates();
		const result = templates.render("welcome", {
			email: "alice@example.com",
			name: "Alice",
		});
		expect(result.html).toContain("Alice");
	});
});

describe("email templates: text contains variable values", () => {
	it("verification text contains the verifyUrl", () => {
		const templates = createEmailTemplates();
		const result = templates.render("verification", {
			email: "alice@example.com",
			verifyUrl: "https://example.com/verify?token=abc",
		});
		expect(result.text).toContain("https://example.com/verify?token=abc");
	});

	it("emailOtp text contains the code", () => {
		const templates = createEmailTemplates();
		const result = templates.render("emailOtp", {
			email: "alice@example.com",
			code: "123987",
		});
		expect(result.text).toContain("123987");
	});

	it("invitation text contains the orgName", () => {
		const templates = createEmailTemplates();
		const result = templates.render("invitation", {
			email: "alice@example.com",
			orgName: "Dev Squad",
			inviteUrl: "https://example.com/inv/1",
		});
		expect(result.text).toContain("Dev Squad");
	});

	it("welcome text contains the user name", () => {
		const templates = createEmailTemplates();
		const result = templates.render("welcome", {
			email: "alice@example.com",
			name: "Bob",
		});
		expect(result.text).toContain("Bob");
	});
});

describe("email templates: HTML is inline CSS and structurally valid", () => {
	const allTemplateNames: EmailTemplateName[] = [
		"verification",
		"passwordReset",
		"magicLink",
		"emailOtp",
		"invitation",
		"welcome",
	];

	const vars: Record<EmailTemplateName, Record<string, string>> = {
		verification: { email: "a@b.com", verifyUrl: "https://example.com/v" },
		passwordReset: { email: "a@b.com", resetUrl: "https://example.com/r" },
		magicLink: { email: "a@b.com", url: "https://example.com/m" },
		emailOtp: { email: "a@b.com", code: "111222" },
		invitation: { email: "a@b.com", orgName: "Org", inviteUrl: "https://example.com/i" },
		welcome: { email: "a@b.com", name: "User" },
	};

	for (const name of allTemplateNames) {
		it(`${name} HTML does not reference external stylesheets`, () => {
			const templates = createEmailTemplates({ appName: "TheAuth" });
			const result = templates.render(name, vars[name] ?? {});
			expect(result.html).not.toContain("<link");
			expect(result.html).not.toContain("@import");
		});

		it(`${name} HTML starts with DOCTYPE`, () => {
			const templates = createEmailTemplates({ appName: "TheAuth" });
			const result = templates.render(name, vars[name] ?? {});
			expect(result.html.trimStart()).toMatch(/^<!DOCTYPE html>/i);
		});
	}
});
