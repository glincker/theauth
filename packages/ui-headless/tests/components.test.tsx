import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
	ApiTokenList,
	DeviceApproval,
	MintTokenForm,
	SessionList,
	StepUpDialog,
	useStepUpRetry,
} from "../src/index.js";
import { calls, errors, renderWith, route } from "./helpers.js";

const sessionLabels = {
	title: "Sessions",
	loading: "Loading",
	empty: "None",
	current: "This device",
	revokeOthers: "Sign out others",
	lastSeen: (iso: string) => `seen ${iso}`,
	revoke: (s: { deviceLabel: string }) => `Revoke ${s.deviceLabel}`,
	error: errors,
};

describe("SessionList", () => {
	const sessions = [
		{ id: "s1", deviceLabel: "Mac", lastSeenAt: "2026-01-01", current: true },
		{ id: "s2", deviceLabel: "Phone", lastSeenAt: "2026-01-02", current: false },
	];

	it("shows label, last seen and current badge, and revokes others via keyboard", async () => {
		const user = userEvent.setup();
		const f = route({
			"GET /auth/sessions": { status: 200, body: { sessions } },
			"GET /auth/me": { status: 200, body: { id: "u" } },
			"DELETE /auth/sessions/s2": { status: 204 },
			"POST /auth/sessions/revoke-others": { status: 200, body: { revoked: 1 } },
		});
		renderWith(<SessionList labels={sessionLabels} />, f);
		const items = await screen.findAllByRole("listitem");
		expect(within(items[0] as HTMLElement).getByText("This device")).toBeInTheDocument();
		expect(within(items[0] as HTMLElement).queryByRole("button")).toBeNull();
		expect(items[1]).toHaveTextContent("seen 2026-01-02");
		expect(items[0]).toHaveAttribute("data-current");

		await user.tab();
		expect(screen.getByRole("button", { name: "Revoke Phone" })).toHaveFocus();
		await user.keyboard("{Enter}");
		await waitFor(() => expect(calls(f)).toContain("DELETE /auth/sessions/s2"));
		await user.click(screen.getByRole("button", { name: "Sign out others" }));
		await waitFor(() => expect(calls(f)).toContain("POST /auth/sessions/revoke-others"));
	});

	it("renders the error code through labels", async () => {
		const f = route({
			"GET /auth/sessions": { status: 200, body: { sessions } },
			"GET /auth/me": { status: 200, body: { id: "u" } },
			"DELETE /auth/sessions/s2": { status: 403, body: { code: "forbidden", message: "x" } },
		});
		renderWith(<SessionList labels={sessionLabels} />, f);
		await userEvent.click(await screen.findByRole("button", { name: "Revoke Phone" }));
		const alert = await screen.findByRole("alert");
		expect(alert).toHaveTextContent("err:forbidden");
		expect(alert).toHaveAttribute("data-error-code", "forbidden");
	});
});

const tokenLabels = {
	title: "Tokens",
	loading: "Loading",
	empty: "No tokens",
	revoked: "Revoked",
	kind: { personal: "Personal", agent: "Agent" },
	lastUsed: (i: string) => `used ${i}`,
	expires: (i: string) => `expires ${i}`,
	delegatedBy: (u: string) => `by ${u}`,
	revoke: (t: { name: string }) => `Revoke ${t.name}`,
	error: errors,
};

describe("ApiTokenList", () => {
	const tokens = [
		{ id: "p1", name: "ci", hint: "tk_a", abilities: [] },
		{ id: "a1", name: "bot", hint: "tk_b", kind: "agent", agentName: "claude", delegatedBy: "u1" },
	];

	it("filters by kind and shows agent metadata", async () => {
		const f = route({ "GET /auth/tokens/": { status: 200, body: { tokens } } });
		renderWith(<ApiTokenList labels={tokenLabels} kind="agent" />, f);
		const item = await screen.findByRole("listitem");
		expect(item).toHaveAttribute("data-kind", "agent");
		expect(item).toHaveTextContent("claude");
		expect(item).toHaveTextContent("by u1");
		expect(screen.queryByText("ci")).toBeNull();
	});

	it("revokes with an accessible name", async () => {
		const f = route({
			"GET /auth/tokens/": { status: 200, body: { tokens } },
			"DELETE /auth/tokens/p1": { status: 204 },
		});
		renderWith(<ApiTokenList labels={tokenLabels} />, f);
		await userEvent.click(await screen.findByRole("button", { name: "Revoke ci" }));
		await waitFor(() => expect(calls(f)).toContain("DELETE /auth/tokens/p1"));
	});
});

const mintLabels = {
	name: "Name",
	agentName: "Agent",
	abilities: "Abilities",
	expiry: "Expiry",
	submit: "Create",
	secretTitle: "Your token",
	secretNotice: "Shown once",
	copy: "Copy",
	copied: "Copied",
	dismiss: "Done",
	error: errors,
};

describe("MintTokenForm", () => {
	const abilities = [
		{ id: "read", label: "Read" },
		{ id: "write", label: "Write" },
	];
	const expiries = [
		{ seconds: 3600, label: "1 hour" },
		{ seconds: 0, label: "Never" },
	];

	it("mints an agent token, reveals the secret once and copies it", async () => {
		const user = userEvent.setup();
		const writeText = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
		const f = route({
			"POST /auth/tokens/": { status: 201, body: { token: "tk_secret", id: "a2", kind: "agent" } },
		});
		renderWith(
			<MintTokenForm labels={mintLabels} abilities={abilities} expiries={expiries} kind="agent" />,
			f,
		);
		await user.type(screen.getByLabelText("Name"), "desk");
		await user.type(screen.getByLabelText("Agent"), "claude");
		await user.click(screen.getByRole("checkbox", { name: "Write" }));
		await user.click(screen.getByRole("button", { name: "Create" }));

		expect(await screen.findByText("tk_secret")).toBeInTheDocument();
		const body = JSON.parse(String(f.mock.calls[0]?.[1].body));
		expect(body).toEqual({
			name: "desk",
			abilities: ["write"],
			kind: "agent",
			agent_name: "claude",
			expires_in: 3600,
		});
		await user.click(screen.getByRole("button", { name: "Copy" }));
		expect(writeText).toHaveBeenCalledWith("tk_secret");
		expect(await screen.findByText("Copied")).toBeInTheDocument();

		await user.click(screen.getByRole("button", { name: "Done" }));
		expect(screen.queryByText("tk_secret")).toBeNull();
		expect(screen.getByLabelText("Name")).toBeInTheDocument();
	});

	it("shows a local code for an empty name and server codes through labels", async () => {
		const user = userEvent.setup();
		const f = route({
			"POST /auth/tokens/": { status: 400, body: { code: "invalid_abilities", message: "x" } },
		});
		renderWith(<MintTokenForm labels={mintLabels} abilities={abilities} />, f);
		await user.click(screen.getByRole("button", { name: "Create" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("err:name_required");
		expect(f).not.toHaveBeenCalled();
		await user.type(screen.getByLabelText("Name"), "x");
		await user.click(screen.getByRole("button", { name: "Create" }));
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("err:invalid_abilities"),
		);
	});
});

const deviceLabels = {
	codeLabel: "Code",
	lookup: "Continue",
	requestFrom: (c: string) => `Request from ${c}`,
	requesterIp: "IP",
	requesterUserAgent: "Browser",
	abilities: "Access",
	approve: "Approve",
	deny: "Deny",
	approved: "Approved",
	denied: "Denied",
	error: errors,
};

describe("DeviceApproval", () => {
	const info = {
		client_name: "cli",
		abilities: ["read"],
		requester_ip: "203.0.113.9",
		requester_user_agent: "curl/8",
		expires_at: "2026-01-01",
	};

	it("looks up a code, shows requester details and approves", async () => {
		const user = userEvent.setup();
		const f = route({
			"POST /auth/device/approve#info": { status: 200, body: info },
			"POST /auth/device/approve#approve": { status: 204 },
		});
		renderWith(<DeviceApproval labels={deviceLabels} />, f);
		expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
		await user.type(screen.getByLabelText("Code"), "ABCD-1234{Enter}");
		expect(await screen.findByText("203.0.113.9")).toBeInTheDocument();
		expect(screen.getByText("curl/8")).toBeInTheDocument();
		await user.click(screen.getByRole("button", { name: "Approve" }));
		expect(await screen.findByRole("status")).toHaveTextContent("Approved");
	});

	it("denies, and shows lookup error codes", async () => {
		const user = userEvent.setup();
		const f = route({
			"POST /auth/device/approve#info": [
				{ status: 404, body: { code: "invalid_user_code", message: "x" } },
				{ status: 200, body: info },
			],
			"POST /auth/device/approve#deny": { status: 204 },
		});
		renderWith(<DeviceApproval labels={deviceLabels} />, f);
		await user.type(screen.getByLabelText("Code"), "BAD{Enter}");
		expect(await screen.findByRole("alert")).toHaveTextContent("err:invalid_user_code");
		await user.clear(screen.getByLabelText("Code"));
		await user.type(screen.getByLabelText("Code"), "GOOD{Enter}");
		await user.click(await screen.findByRole("button", { name: "Deny" }));
		expect(await screen.findByRole("status")).toHaveTextContent("Denied");
	});
});

const stepLabels = {
	title: "Confirm it is you",
	methods: { password: "Password", totp: "Authenticator", passkey: "Passkey" },
	password: "Your password",
	totpCode: "Code",
	passkeyPrompt: "Use your passkey",
	submit: "Confirm",
	cancel: "Cancel",
	error: errors,
};

describe("StepUpDialog", () => {
	it("is an accessible dialog with arrow-key tabs and password submit", async () => {
		const user = userEvent.setup();
		const onElevated = vi.fn();
		const f = route({ "POST /auth/step-up": { status: 200, body: { elevated_until: "t" } } });
		renderWith(
			<StepUpDialog open onClose={() => {}} onElevated={onElevated} labels={stepLabels} />,
			f,
		);
		const dialog = screen.getByRole("dialog", { name: "Confirm it is you" });
		expect(dialog).toHaveAttribute("aria-modal", "true");
		const tabs = screen.getAllByRole("tab");
		expect(tabs.map((t) => t.textContent)).toEqual(["Password", "Authenticator"]);
		expect(screen.getByRole("tab", { name: "Password" })).toHaveAttribute("aria-selected", "true");
		screen.getByRole("tab", { name: "Password" }).focus();
		await user.keyboard("{ArrowRight}");
		expect(screen.getByRole("tab", { name: "Authenticator" })).toHaveFocus();
		expect(screen.getByRole("tabpanel")).toHaveAccessibleName("Authenticator");
		await user.keyboard("{ArrowLeft}");
		await user.type(screen.getByLabelText("Your password"), "pw{Enter}");
		await waitFor(() => expect(onElevated).toHaveBeenCalled());
		expect(JSON.parse(String(f.mock.calls[0]?.[1].body))).toEqual({
			method: "password",
			password: "pw",
		});
	});

	it("closes on Escape and shows error codes", async () => {
		const user = userEvent.setup();
		const onClose = vi.fn();
		const f = route({
			"POST /auth/step-up": { status: 401, body: { code: "invalid_credentials", message: "x" } },
		});
		renderWith(
			<StepUpDialog open onClose={onClose} onElevated={() => {}} labels={stepLabels} />,
			f,
		);
		await user.type(screen.getByLabelText("Your password"), "bad{Enter}");
		expect(await screen.findByRole("alert")).toHaveTextContent("err:invalid_credentials");
		await user.keyboard("{Escape}");
		expect(onClose).toHaveBeenCalled();
	});

	it("renders nothing when closed", () => {
		renderWith(
			<StepUpDialog open={false} onClose={() => {}} onElevated={() => {}} labels={stepLabels} />,
			route({}),
		);
		expect(screen.queryByRole("dialog")).toBeNull();
	});
});

describe("useStepUpRetry", () => {
	function Harness({ labels }: { labels: typeof tokenLabels }) {
		const { run, dialogProps } = useStepUpRetry();
		return (
			<>
				<ApiTokenList labels={labels} run={run} />
				<StepUpDialog {...dialogProps} labels={stepLabels} />
			</>
		);
	}

	it("opens on recent_auth_required then retries the revoke after elevation", async () => {
		const user = userEvent.setup();
		const f = route({
			"GET /auth/tokens/": {
				status: 200,
				body: { tokens: [{ id: "p1", name: "ci", hint: "h", abilities: [] }] },
			},
			"DELETE /auth/tokens/p1": [
				{ status: 403, body: { code: "auth.recent_auth_required", message: "x" } },
				{ status: 204 },
			],
			"POST /auth/step-up": { status: 200, body: { elevated_until: "t" } },
		});
		renderWith(<Harness labels={tokenLabels} />, f);
		await user.click(await screen.findByRole("button", { name: "Revoke ci" }));
		const dialog = await screen.findByRole("dialog");
		expect(screen.queryByText("err:auth.recent_auth_required")).toBeNull();
		await user.type(within(dialog).getByLabelText("Your password"), "pw{Enter}");
		await waitFor(() =>
			expect(calls(f).filter((c) => c === "DELETE /auth/tokens/p1")).toHaveLength(2),
		);
		await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
		await act(async () => {});
	});
});
