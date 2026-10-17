import type { Preset } from "./presets.js";
import { DEFAULT_POLICY, PRESETS } from "./presets.js";
import type { KeyMaterial } from "./scenario.js";
import { newKey, parsePolicy, runScenario, verifyReceiptJson } from "./scenario.js";
import { buildSnippet } from "./snippet.js";
import "./style.css";

function el<T extends HTMLElement>(id: string): T {
	const node = document.getElementById(id);
	if (!node) throw new Error(`missing element #${id}`);
	return node as T;
}

function h<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	attrs: Record<string, string> = {},
	...children: Array<string | Node>
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
	for (const c of children) node.append(c);
	return node;
}

const presetsEl = el<HTMLDivElement>("presets");
const descEl = el<HTMLParagraphElement>("preset-desc");
const policyEl = el<HTMLTextAreaElement>("policy");
const policyErr = el<HTMLParagraphElement>("policy-error");
const runBtn = el<HTMLButtonElement>("run");
const resetBtn = el<HTMLButtonElement>("reset");
const resultEl = el<HTMLDivElement>("result");
const receiptEl = el<HTMLDivElement>("receipt");
const codeEl = el<HTMLPreElement>("code");
const copyBtn = el<HTMLButtonElement>("copy");
const copyStatus = el<HTMLSpanElement>("copy-status");

let selected: Preset = PRESETS[0] as Preset;
let key: KeyMaterial | undefined;

const policyText = () => JSON.stringify(DEFAULT_POLICY, null, 2);

function refreshCode(): void {
	const parsed = parsePolicy(policyEl.value);
	codeEl.textContent = buildSnippet(
		selected.call,
		"policy" in parsed ? parsed.policy : DEFAULT_POLICY,
	);
}

function renderPresets(): void {
	presetsEl.replaceChildren();
	PRESETS.forEach((p, i) => {
		const id = `preset-${p.id}`;
		const input = h("input", { type: "radio", name: "preset", id, value: p.id });
		input.checked = p.id === selected.id;
		input.addEventListener("change", () => select(p));
		const label = h("label", { for: id, class: "preset" }, h("span", {}, `${i + 1}. ${p.title}`));
		presetsEl.append(input, label);
	});
	descEl.textContent = selected.summary;
}

function select(p: Preset): void {
	selected = p;
	descEl.textContent = p.summary;
	resultEl.replaceChildren(h("p", { class: "muted" }, "Press Run the tool call."));
	receiptEl.replaceChildren(h("p", { class: "muted" }, "The receipt appears after a run."));
	refreshCode();
}

function badge(outcome: string): HTMLElement {
	const text = outcome === "allow" ? "Allowed" : outcome === "deny" ? "Blocked" : "Needs approval";
	return h("span", { class: `badge badge-${outcome}` }, text);
}

function row(label: string, value: string | Node): HTMLElement[] {
	return [h("dt", {}, label), h("dd", {}, value)];
}

function labelChips(labels: Record<string, string[]>): Node {
	const entries = Object.entries(labels);
	if (entries.length === 0) return h("span", { class: "muted" }, "none");
	const wrap = h("span", { class: "chips" });
	for (const [arg, ls] of entries) {
		for (const l of ls) wrap.append(h("span", { class: "chip" }, `${arg}: ${l}`));
	}
	return wrap;
}

async function run(): Promise<void> {
	const parsed = parsePolicy(policyEl.value);
	if ("error" in parsed) {
		policyErr.textContent = parsed.error;
		policyEl.setAttribute("aria-invalid", "true");
		policyEl.focus();
		return;
	}
	policyErr.textContent = "";
	policyEl.removeAttribute("aria-invalid");
	runBtn.disabled = true;
	runBtn.textContent = "Running...";
	resultEl.setAttribute("aria-busy", "true");
	try {
		key ??= await newKey();
		const r = await runScenario(selected.call, parsed.policy, key);
		const dl = h("dl", { class: "facts" });
		dl.append(
			...row("Decision", badge(r.outcome)),
			...row("Reason", r.reason || "none"),
			...(r.code ? row("Code", h("code", {}, r.code)) : []),
			...(r.tier ? row("Escalation tier", h("code", {}, r.tier)) : []),
			...(r.approvalRequestId ? row("Approval request", h("code", {}, r.approvalRequestId)) : []),
			...row("Taint labels seen", labelChips(r.labels)),
			...row("Taint verdict", r.taint ? r.taint.verdict : "no provenance supplied"),
			...row("Tool executed", r.toolRan ? "yes" : "no"),
		);
		resultEl.replaceChildren(dl);
		await renderReceipt(r);
	} catch (error) {
		resultEl.replaceChildren(
			h(
				"p",
				{ class: "error", role: "alert" },
				error instanceof Error ? error.message : "Run failed",
			),
		);
	} finally {
		resultEl.removeAttribute("aria-busy");
		runBtn.disabled = false;
		runBtn.textContent = "Run the tool call";
	}
}

async function renderReceipt(r: Awaited<ReturnType<typeof runScenario>>): Promise<void> {
	if (!r.receipt) {
		receiptEl.replaceChildren(h("p", { class: "error" }, r.receiptError ?? "No receipt."));
		return;
	}
	const receipt = r.receipt;
	const status = h("p", { class: r.verified ? "ok" : "error", role: "status" });
	status.textContent = r.verified
		? "Verified in this browser: Ed25519 signature on the tree head and Merkle inclusion proof both check out."
		: `Verification failed: ${r.verifyReason ?? "unknown"}`;

	const area = h("textarea", {
		id: "receipt-json",
		rows: "14",
		spellcheck: "false",
		"aria-label": "Receipt JSON, editable",
	});
	area.value = JSON.stringify(receipt, null, 2);
	const out = h("p", { role: "status", class: "muted" });
	const verifyBtn = h("button", { type: "button" }, "Verify again");
	verifyBtn.addEventListener("click", async () => {
		const v = await verifyReceiptJson(area.value, r.publicKey);
		out.className = v.valid ? "ok" : "error";
		out.textContent = v.valid ? "Valid." : `Invalid: ${v.reason ?? "unknown"}`;
	});
	const tamperBtn = h("button", { type: "button" }, "Tamper with the receipt");
	tamperBtn.addEventListener("click", () => {
		area.value = area.value.replace(
			/"rootHash": "([0-9a-f])/,
			(_m, c: string) => `"rootHash": "${c === "0" ? "1" : "0"}`,
		);
		out.className = "muted";
		out.textContent = "Changed the first digit of rootHash. Press Verify again.";
	});
	const proof = receipt.proof;
	const dl = h("dl", { class: "facts" });
	dl.append(
		...row("Row id", h("code", {}, receipt.decision.rowId)),
		...row("Tree size", String(receipt.checkpoint.size)),
		...row("Leaf index", String(proof.leafIndex)),
		...row("Proof path length", `${proof.path.length} hashes`),
		...row("Root hash", h("code", { class: "wrap" }, receipt.checkpoint.rootHash)),
		...row("Signing key", h("code", {}, `${r.publicKey.keyId} (Ed25519, generated in this tab)`)),
	);
	receiptEl.replaceChildren(
		status,
		dl,
		h("label", { for: "receipt-json" }, "Receipt JSON. Edit it, then verify."),
		area,
		h("div", { class: "row" }, verifyBtn, tamperBtn),
		out,
	);
}

runBtn.addEventListener("click", () => void run());
resetBtn.addEventListener("click", () => {
	policyEl.value = policyText();
	policyErr.textContent = "";
	refreshCode();
});
policyEl.addEventListener("input", refreshCode);
copyBtn.addEventListener("click", async () => {
	try {
		await navigator.clipboard.writeText(codeEl.textContent ?? "");
		copyStatus.textContent = "Copied.";
	} catch {
		copyStatus.textContent = "Copy failed. Select the code and copy it by hand.";
	}
});

policyEl.value = policyText();
renderPresets();
refreshCode();
