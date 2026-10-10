import type { Preset } from "./presets.js";

const STYLES = `
:root {
  --bg: #0c0c0e;
  --panel: #151518;
  --panel-2: #1c1c21;
  --line: #2e2e36;
  --text: #ecebe6;
  --muted: #a3a3ad;
  --gold: #c9a84c;
  --gold-deep: #8b6914;
  --ok: #7ee2a8;
  --deny: #ff9b8f;
  --focus: #ffd866;
  color-scheme: dark;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
  line-height: 1.55;
}
code, pre, input.mono, td.mono, .mono {
  font-family: "JetBrains Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
}
.banner {
  background: var(--gold-deep);
  color: #fff;
  padding: 10px 16px;
  font-size: 0.9rem;
  text-align: center;
}
main { max-width: 860px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 1.75rem; margin: 8px 0 4px; color: var(--gold); }
.lede { color: var(--muted); margin: 0 0 24px; }
section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 16px;
}
section[aria-disabled="true"] { opacity: 0.55; }
h2 { font-size: 1.05rem; margin: 0 0 4px; }
.step { color: var(--gold); font-variant-numeric: tabular-nums; margin-right: 6px; }
.hint { color: var(--muted); font-size: 0.9rem; margin: 0 0 14px; }
label, legend { display: block; font-weight: 600; font-size: 0.9rem; margin-bottom: 4px; }
fieldset { border: 0; padding: 0; margin: 0 0 14px; }
fieldset.spaced { margin-top: 14px; }
input[type="text"] {
  width: 100%;
  background: var(--bg);
  color: var(--text);
  border: 1px solid #55555f;
  border-radius: 6px;
  padding: 9px 10px;
  font-size: 0.95rem;
}
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
@media (max-width: 560px) { .row { grid-template-columns: 1fr; } }
.preset {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  background: var(--panel-2);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 8px;
  font-weight: 400;
  cursor: pointer;
}
.preset strong { display: block; }
.preset small { color: var(--muted); }
button {
  font: inherit;
  font-weight: 600;
  border-radius: 6px;
  padding: 9px 16px;
  border: 1px solid var(--gold);
  background: var(--gold);
  color: #17140a;
  cursor: pointer;
}
button.ghost { background: transparent; color: var(--text); border-color: #6b6b76; }
button.danger { background: transparent; color: var(--deny); border-color: var(--deny); }
button:disabled { opacity: 0.5; cursor: not-allowed; }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }
.token {
  display: block;
  background: var(--bg);
  border: 1px dashed var(--gold);
  border-radius: 6px;
  padding: 10px;
  word-break: break-all;
  font-size: 0.85rem;
  margin: 10px 0;
}
.verdict {
  margin-top: 14px;
  padding: 12px 14px;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: var(--panel-2);
}
.verdict.allowed { border-color: var(--ok); }
.verdict.denied { border-color: var(--deny); }
.verdict .label { font-weight: 700; letter-spacing: 0.04em; }
.verdict.allowed .label { color: var(--ok); }
.verdict.denied .label { color: var(--deny); }
.error { color: var(--deny); margin: 10px 0 0; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
caption { text-align: left; color: var(--muted); padding-bottom: 8px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; white-space: nowrap; }
.pill { font-weight: 700; }
.pill.allowed { color: var(--ok); }
.pill.denied, .pill.rate_limited { color: var(--deny); }
pre {
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 10px;
  overflow-x: auto;
  font-size: 0.8rem;
  margin: 8px 0 0;
}
footer { color: var(--muted); font-size: 0.85rem; margin-top: 24px; }
.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
}
@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
`;

const SCRIPT = `
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var state = { agentId: null, token: null };

  function api(path, method, body) {
    return fetch(path, {
      method: method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined
    }).then(function (res) {
      return res.json().then(function (json) { return { ok: res.ok, status: res.status, json: json }; });
    });
  }

  function errorText(r) {
    var e = r.json && r.json.error;
    if (e && e.message) return e.message;
    return "Request failed (" + r.status + ")";
  }

  function setBusy(btn, busy) { btn.disabled = busy; }

  function enable(id, on) {
    var el = $(id);
    el.setAttribute("aria-disabled", on ? "false" : "true");
    var controls = el.querySelectorAll("input, button");
    for (var i = 0; i < controls.length; i++) controls[i].disabled = !on;
  }

  function showPresetPermissions(presets) {
    var checked = document.querySelector('input[name="preset"]:checked');
    for (var i = 0; i < presets.length; i++) {
      if (checked && presets[i].id === checked.value) {
        $("preset-json").textContent = JSON.stringify(presets[i].permissions, null, 2);
      }
    }
  }

  function renderAudit(rows) {
    var body = $("audit-body");
    body.textContent = "";
    $("audit-empty").hidden = rows.length > 0;
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      var cells = [
        [new Date(row.at).toLocaleTimeString(), ""],
        [row.agentId.slice(0, 12), "mono"],
        [row.action, "mono"],
        [row.resource, "mono"],
        [row.result.toUpperCase(), "pill " + row.result],
        [row.reason || "", ""]
      ];
      cells.forEach(function (c) {
        var td = document.createElement("td");
        td.textContent = c[0];
        if (c[1]) td.className = c[1];
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  }

  function refreshAudit() {
    if (!state.agentId) return Promise.resolve();
    return api("/api/audit?agentId=" + encodeURIComponent(state.agentId), "GET").then(function (r) {
      if (r.ok) renderAudit(r.json.rows);
    });
  }

  function setVerdict(kind, text, reason) {
    var box = $("verdict");
    box.hidden = false;
    box.className = "verdict " + kind;
    $("verdict-label").textContent = text;
    $("verdict-reason").textContent = reason || "";
  }

  fetch("/api/info").then(function (r) { return r.json(); }).then(function (info) {
    $("ttl").textContent = String(info.ttlMinutes);
    $("preset-list").addEventListener("change", function () { showPresetPermissions(info.presets); });
    showPresetPermissions(info.presets);
  });

  $("create-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = $("create-btn");
    setBusy(btn, true);
    $("create-error").textContent = "";
    var preset = document.querySelector('input[name="preset"]:checked');
    api("/api/agents", "POST", { name: $("agent-name").value, preset: preset ? preset.value : "reader" })
      .then(function (r) {
        setBusy(btn, false);
        if (!r.ok) { $("create-error").textContent = errorText(r); return; }
        state.agentId = r.json.agent.id;
        state.token = r.json.token;
        $("agent-id").textContent = r.json.agent.id;
        $("token-value").textContent = r.json.token;
        $("token-box").hidden = false;
        $("token-gone").hidden = true;
        $("verdict").hidden = true;
        $("revoked-note").hidden = true;
        enable("step-try", true);
        enable("step-audit", true);
        enable("step-revoke", true);
        renderAudit([]);
        $("token-value").focus();
      });
  });

  $("hide-token").addEventListener("click", function () {
    state.token = null;
    $("token-value").textContent = "";
    $("token-box").hidden = true;
    $("token-gone").hidden = false;
    $("action").focus();
  });

  $("copy-token").addEventListener("click", function () {
    if (!state.token || !navigator.clipboard) return;
    navigator.clipboard.writeText(state.token).then(function () {
      $("copy-status").textContent = "Copied.";
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll("[data-fill]"), function (btn) {
    btn.addEventListener("click", function () {
      var parts = btn.getAttribute("data-fill").split(" ");
      $("action").value = parts[0];
      $("resource").value = parts[1];
      $("action").focus();
    });
  });

  $("try-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (!state.agentId) return;
    var btn = $("try-btn");
    setBusy(btn, true);
    $("try-error").textContent = "";
    api("/api/authorize", "POST", {
      agentId: state.agentId,
      action: $("action").value,
      resource: $("resource").value
    }).then(function (r) {
      setBusy(btn, false);
      if (!r.ok) { $("try-error").textContent = errorText(r); return; }
      setVerdict(r.json.allowed ? "allowed" : "denied", r.json.allowed ? "ALLOWED" : "DENIED", r.json.reason);
      return refreshAudit();
    });
  });

  $("revoke-btn").addEventListener("click", function () {
    if (!state.agentId) return;
    var btn = $("revoke-btn");
    setBusy(btn, true);
    api("/api/agents/" + encodeURIComponent(state.agentId) + "/revoke", "POST").then(function (r) {
      setBusy(btn, false);
      if (!r.ok) { $("revoke-error").textContent = errorText(r); return; }
      $("revoked-note").hidden = false;
      $("action").focus();
    });
  });
})();
`;

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

function presetRadios(presets: readonly Preset[]): string {
	return presets
		.map(
			(p, i) => `<label class="preset">
          <input type="radio" name="preset" value="${escapeHtml(p.id)}"${i === 0 ? " checked" : ""}>
          <span><strong>${escapeHtml(p.label)}</strong><small>${escapeHtml(p.description)}</small></span>
        </label>`,
		)
		.join("\n        ");
}

export function renderPage(nonce: string, presets: readonly Preset[]): string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>TheAuth agent demo</title>
<style nonce="${nonce}">${STYLES}</style>
</head>
<body>
<div class="banner" role="note">
  Shared sandbox. Everyone sees the same database and it resets: agents and audit rows are deleted
  <span id="ttl">60</span> minutes after creation. Do not type personal data.
</div>
<main>
  <h1>Give an agent an identity, then take it away</h1>
  <p class="lede">Create an agent, let it act, watch a request get denied, then revoke it and watch the same request fail. Each step calls the real TheAuth SDK.</p>

  <section id="step-create" aria-labelledby="h-create">
    <h2 id="h-create"><span class="step">1.</span>Create an agent</h2>
    <p class="hint">An agent is a named identity with an explicit list of permissions.</p>
    <form id="create-form">
      <div>
        <label for="agent-name">Agent name</label>
        <input id="agent-name" type="text" value="report-bot" maxlength="32" autocomplete="off" required>
      </div>
      <fieldset id="preset-list" class="spaced">
        <legend>Permissions</legend>
        ${presetRadios(presets)}
      </fieldset>
      <p class="hint">Permissions sent to the SDK:</p>
      <pre id="preset-json" class="mono" aria-live="polite"></pre>
      <div class="actions"><button id="create-btn" type="submit">Create agent</button></div>
      <p id="create-error" class="error" role="alert"></p>
    </form>
  </section>

  <section id="step-token" aria-labelledby="h-token">
    <h2 id="h-token"><span class="step">2.</span>Agent token</h2>
    <p class="hint">The token is shown once. The server stores only a hash of it, so it cannot show it to you again.</p>
    <p>Agent id: <code id="agent-id" class="mono">none yet</code></p>
    <div id="token-box" hidden>
      <code id="token-value" class="token mono" tabindex="-1"></code>
      <div class="actions">
        <button id="copy-token" type="button" class="ghost">Copy token</button>
        <button id="hide-token" type="button" class="ghost">Hide it for good</button>
      </div>
      <p id="copy-status" class="hint" role="status"></p>
    </div>
    <p id="token-gone" class="hint" hidden>The token is gone from this page. That is how it works for real agents too: store it when you get it.</p>
  </section>

  <section id="step-try" aria-labelledby="h-try" aria-disabled="true">
    <h2 id="h-try"><span class="step">3.</span>Try an action</h2>
    <p class="hint">Ask the SDK whether this agent may do something. Every answer lands in the audit log.</p>
    <form id="try-form">
      <div class="row">
        <div>
          <label for="action">Action</label>
          <input id="action" class="mono" type="text" value="read" maxlength="32" autocomplete="off" required disabled>
        </div>
        <div>
          <label for="resource">Resource</label>
          <input id="resource" class="mono" type="text" value="docs:handbook" maxlength="64" autocomplete="off" required disabled>
        </div>
      </div>
      <div class="actions">
        <button id="try-btn" type="submit" disabled>Check permission</button>
        <button type="button" class="ghost" data-fill="read docs:handbook" disabled>read docs:handbook</button>
        <button type="button" class="ghost" data-fill="write docs:handbook" disabled>write docs:handbook</button>
        <button type="button" class="ghost" data-fill="delete billing:invoices" disabled>delete billing:invoices</button>
      </div>
      <p id="try-error" class="error" role="alert"></p>
    </form>
    <div id="verdict" class="verdict" hidden role="status">
      <div id="verdict-label" class="label"></div>
      <div id="verdict-reason"></div>
    </div>
  </section>

  <section id="step-audit" aria-labelledby="h-audit" aria-disabled="true">
    <h2 id="h-audit"><span class="step">4.</span>Audit log</h2>
    <p class="hint">What the SDK recorded for this agent.</p>
    <div class="table-wrap">
      <table>
        <caption class="sr-only">Audit log for this agent</caption>
        <thead>
          <tr><th scope="col">Time</th><th scope="col">Agent</th><th scope="col">Action</th><th scope="col">Resource</th><th scope="col">Result</th><th scope="col">Reason</th></tr>
        </thead>
        <tbody id="audit-body"></tbody>
      </table>
    </div>
    <p id="audit-empty" class="hint">No entries yet.</p>
  </section>

  <section id="step-revoke" aria-labelledby="h-revoke" aria-disabled="true">
    <h2 id="h-revoke"><span class="step">5.</span>Revoke this agent</h2>
    <p class="hint">Revoking takes effect immediately. After you revoke, go back to step 3 and send the same request again.</p>
    <div class="actions"><button id="revoke-btn" type="button" class="danger" disabled>Revoke this agent</button></div>
    <p id="revoked-note" class="hint" role="status" hidden>Revoked. Run the allowed request from step 3 again and compare the audit log.</p>
    <p id="revoke-error" class="error" role="alert"></p>
  </section>

  <footer>
    TheAuth is open source and 0.x. This page is a demo of the SDK, not a hosted product.
    Rate limits and caps apply per client. Your IP address is not stored; a short keyed fingerprint of it is kept on your agent and deleted with it.
  </footer>
</main>
<script nonce="${nonce}">${SCRIPT}</script>
</body>
</html>`;
}
