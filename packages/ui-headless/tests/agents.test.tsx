import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AgentList, AgentRegisterForm } from "../src/index.js";
import { calls, errors, renderWith, route } from "./helpers.js";

const listLabels = {
	title: "Agents",
	loading: "Loading",
	empty: "None",
	revoked: "Revoked",
	status: (s: string) => `status ${s}`,
	lastActive: (i: string) => `active ${i}`,
	revoke: (a: { name: string }) => `Revoke ${a.name}`,
	error: errors,
};

const formLabels = {
	name: "Name",
	description: "Description",
	scope: "Scopes",
	submit: "Register",
	secretTitle: "Agent secret",
	secretNotice: "Shown once",
	clientId: "Client ID",
	copy: "Copy",
	copied: "Copied",
	dismiss: "Done",
	error: errors,
};

const agents = [
	{ id: "a1", name: "bot", status: "active", clientId: "cid1", createdAt: "x" },
	{ id: "a2", name: "old", status: "revoked", clientId: "cid2", createdAt: "x" },
];

describe("AgentList", () => {
	it("renders agents and hides revoke on revoked ones", async () => {
		const f = route({ "GET /auth/account/agents": { status: 200, body: { agents } } });
		renderWith(<AgentList labels={listLabels} />, f);
		const items = await screen.findAllByRole("listitem");
		expect(items[0]).toHaveAttribute("data-status", "active");
		expect(items[1]).toHaveAttribute("data-revoked", "");
		expect(screen.getByRole("button", { name: "Revoke bot" })).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Revoke old" })).toBeNull();
	});

	it("revokes", async () => {
		const f = route({
			"GET /auth/account/agents": { status: 200, body: { agents } },
			"DELETE /auth/account/agents/a1": { status: 204 },
		});
		renderWith(<AgentList labels={listLabels} />, f);
		await userEvent.click(await screen.findByRole("button", { name: "Revoke bot" }));
		await waitFor(() => expect(calls(f)).toContain("DELETE /auth/account/agents/a1"));
	});

	it("shows the error code mapped by labels", async () => {
		const f = route({
			"GET /auth/account/agents": { status: 404, body: { code: "not_found", message: "m" } },
		});
		renderWith(<AgentList labels={listLabels} />, f);
		expect(await screen.findByRole("alert")).toHaveTextContent("err:not_found");
	});

	it("shows the empty state", async () => {
		const f = route({ "GET /auth/account/agents": { status: 200, body: { agents: [] } } });
		renderWith(<AgentList labels={listLabels} />, f);
		expect(await screen.findByText("None")).toBeInTheDocument();
	});
});

describe("AgentRegisterForm", () => {
	it("requires a name before calling the server", async () => {
		const f = route({});
		renderWith(<AgentRegisterForm labels={formLabels} />, f);
		await userEvent.click(screen.getByRole("button", { name: "Register" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("err:name_required");
		expect(calls(f).filter((c) => c.startsWith("POST"))).toEqual([]);
	});

	it("registers with scopes and shows the secret once", async () => {
		const f = route({
			"POST /auth/account/agents": {
				status: 201,
				body: { agent: agents[0], credential: { clientId: "cid1", secret: "s3cret" } },
			},
			"GET /auth/account/agents": { status: 200, body: { agents } },
		});
		renderWith(
			<AgentRegisterForm labels={formLabels} scopes={[{ id: "read", label: "Read" }]} />,
			f,
		);
		await userEvent.type(screen.getByLabelText("Name"), "bot");
		await userEvent.click(screen.getByLabelText("Read"));
		await userEvent.click(screen.getByRole("button", { name: "Register" }));
		expect(await screen.findByText("s3cret")).toBeInTheDocument();
		const post = f.mock.calls.find(([, init]) => init.method === "POST");
		expect(JSON.parse(String(post?.[1].body))).toEqual({ name: "bot", scope: ["read"] });
		await userEvent.click(screen.getByRole("button", { name: "Done" }));
		expect(screen.queryByText("s3cret")).toBeNull();
	});
});
