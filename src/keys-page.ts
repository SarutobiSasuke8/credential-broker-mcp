/**
 * The key manager page. Self-contained: no external scripts, styles, or
 * fonts, so the strict CSP in keys-ui.ts holds. The session token arrives in
 * the URL fragment and is moved into memory, then wiped from the address bar.
 */
export function renderKeysPage(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Broker Keys</title>
<style nonce="${nonce}">
:root {
  --bg: #f6f5f2; --panel: #ffffff; --ink: #1d1c1a; --muted: #6b6862; --line: #e3e0da;
  --accent: #2f5d50; --accent-ink: #ffffff; --ok: #2f7a4a; --ok-bg: #e5f3ea; --warn: #9a5b00; --warn-bg: #fbf0dc;
  --bad: #a3322b; --bad-bg: #fbe7e5; --field: #fbfaf8; --radius: 10px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161716; --panel: #1f201f; --ink: #ecebe7; --muted: #a09d96; --line: #333431;
    --accent: #7fb8a4; --accent-ink: #10201b; --ok: #7fcf98; --ok-bg: #1d3325; --warn: #e8b25c; --warn-bg: #362a14;
    --bad: #f08a80; --bad-bg: #3a1f1c; --field: #191a19;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 860px; margin: 0 auto; padding: 28px 16px 64px; }
header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 20px; }
h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 16px; margin: 0 0 12px; }
.sub { color: var(--muted); font-size: 13px; margin: 0; word-break: break-all; }
section { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px; margin-bottom: 16px; }
.card { border: 1px solid var(--line); border-radius: var(--radius); padding: 14px; margin-top: 10px; }
.card-top { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; flex-wrap: wrap; }
.name { font-weight: 600; font-size: 15px; }
.meta { color: var(--muted); font-size: 13px; margin-top: 2px; word-break: break-all; }
.pill { font-size: 12px; font-weight: 600; padding: 2px 9px; border-radius: 999px; white-space: nowrap; }
.pill.keychain { background: var(--ok-bg); color: var(--ok); }
.pill.env { background: var(--ok-bg); color: var(--ok); }
.pill.missing { background: var(--warn-bg); color: var(--warn); }
.row { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.row > input { flex: 1 1 240px; }
input, select { font: inherit; color: inherit; background: var(--field); border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; min-width: 0; }
input:focus, select:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
button { font: inherit; font-weight: 600; border-radius: 8px; padding: 8px 14px; cursor: pointer; border: 1px solid var(--line); background: var(--field); color: var(--ink); }
button.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
button.ghost { background: transparent; }
button:disabled { opacity: 0.6; cursor: progress; }
.result { font-size: 13px; margin-top: 8px; min-height: 0; }
.result.ok { color: var(--ok); } .result.bad { color: var(--bad); } .result.warn { color: var(--warn); }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.grid label { display: flex; flex-direction: column; gap: 4px; font-size: 13px; color: var(--muted); }
.grid .full { grid-column: 1 / -1; }
.grid label input, .grid label select { color: var(--ink); font-size: 15px; }
.check { display: flex; gap: 8px; align-items: flex-start; font-size: 13px; color: var(--muted); grid-column: 1 / -1; }
.hint { font-size: 12px; color: var(--muted); }
.banner { padding: 12px 14px; border-radius: var(--radius); margin-bottom: 16px; font-size: 14px; }
.banner.bad { background: var(--bad-bg); color: var(--bad); }
.banner.warn { background: var(--warn-bg); color: var(--warn); }
.empty { color: var(--muted); font-size: 14px; }
pre { background: var(--field); border: 1px solid var(--line); border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 12.5px; margin: 8px 0; white-space: pre-wrap; word-break: break-all; }
details summary { cursor: pointer; font-weight: 600; }
.hidden { display: none !important; }
.irow { display: grid; grid-template-columns: auto 1fr 200px 190px; gap: 10px; align-items: center; padding: 10px 0; border-top: 1px solid var(--line); }
.irow:first-child { border-top: 0; }
.irow .src { font-size: 12px; color: var(--muted); word-break: break-all; }
.irow .flag { font-size: 12px; font-weight: 600; }
.irow .flag.warn { color: var(--warn); } .irow .flag.ok { color: var(--ok); } .irow .flag.bad { color: var(--bad); }
.irow input[type=text] { width: 100%; }
.import-controls select { margin-left: 6px; }
h3 { font-size: 14px; margin: 18px 0 4px; }
@media (max-width: 640px) { .irow { grid-template-columns: auto 1fr; } .irow > :nth-child(3), .irow > :nth-child(4) { grid-column: 2; } }
@media (max-width: 640px) { .grid { grid-template-columns: 1fr; } header { flex-direction: column; } }
</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>Broker keys</h1>
      <p class="sub" id="where">Loading…</p>
    </div>
    <button class="ghost" id="close">Close</button>
  </header>

  <div id="banner"></div>

  <section>
    <h2>Your APIs</h2>
    <div id="list"><p class="empty">Loading…</p></div>
    <div id="storedOnly"></div>
  </section>

  <section>
    <h2>Import keys already on this computer</h2>
    <p class="hint">Looks in your Windows user environment variables, MCP configs (Claude Code, Claude Desktop, Cursor), and .env files under Documents and C:\\Dev. Keys are read by the key manager itself and never shown here. Your original copies are left exactly as they are.</p>
    <div class="row"><button class="primary" id="scan">Find my keys</button></div>
    <div id="importArea" class="hidden">
      <div id="importRows"></div>
      <div class="row import-controls">
        <label class="hint">Give read access to new APIs: <select id="importAgent"></select></label>
        <input id="importNewAgent" class="hidden" placeholder="claude" pattern="[a-z0-9][a-z0-9._-]{1,63}">
      </div>
      <div class="row"><button class="primary" id="importGo">Import selected</button></div>
      <div class="result" id="importResult"></div>
    </div>
  </section>

  <section>
    <h2>Add an API</h2>
    <form id="add" class="grid" autocomplete="off">
      <label>Short name
        <input name="id" placeholder="openai" required pattern="[a-z0-9][a-z0-9._-]{1,63}">
        <span class="hint">Lowercase, used by the agent to pick this key.</span>
      </label>
      <label>What it is
        <input name="description" placeholder="OpenAI API, personal project key">
      </label>
      <label class="full">Base URL
        <input name="baseUrl" placeholder="https://api.openai.com/v1" required>
        <span class="hint">The agent can only reach paths under this address.</span>
      </label>
      <label>How the key is sent
        <select name="kind">
          <option value="bearer">Authorization: Bearer &lt;key&gt; (most APIs)</option>
          <option value="header">Custom header (e.g. x-api-key)</option>
          <option value="basic">Basic auth (user:password)</option>
          <option value="query">In the URL (?api_key=…)</option>
        </select>
      </label>
      <label id="paramWrap" class="hidden"><span id="paramLabel">Header name</span>
        <input name="paramName" placeholder="x-api-key">
      </label>
      <label class="check hidden" id="queryRisk"><input type="checkbox" name="acknowledgeQueryRisk">
        <span>I understand keys in URLs often end up in server and proxy logs. Prefer a header if the API supports one.</span>
      </label>
      <label class="full">API key
        <input name="value" type="password" placeholder="Paste the key" spellcheck="false">
        <span class="hint">Saved to Windows Credential Manager. Never written to the policy file or shown again.</span>
      </label>
      <label>Give read access to
        <select name="agent"></select>
      </label>
      <label id="newAgentWrap" class="hidden">New agent name
        <input name="newAgent" placeholder="claude" pattern="[a-z0-9][a-z0-9._-]{1,63}">
      </label>
      <label class="full">Query parameters the agent may use (optional)
        <input name="queryParams" placeholder="q, limit, page">
        <span class="hint">Read access means GET on any path under the base URL. Any query parameter not listed is refused. Write access (POST, DELETE…) stays a hand-written policy decision.</span>
      </label>
      <div class="full">
        <button class="primary" type="submit">Add API</button>
        <div class="result" id="addResult"></div>
      </div>
    </form>
  </section>

  <section>
    <details id="connect">
      <summary>Connect to Claude Code</summary>
      <p class="hint">Run once per agent identity. The broker reads keys from Credential Manager at start-up, so nothing secret goes in this command.</p>
      <label class="hint">Agent <select id="connectAgent"></select></label>
      <pre id="connectCmd"></pre>
      <button id="copyCmd">Copy</button>
      <p class="hint">Restart Claude Code after adding or changing a key: the broker loads keys once when it starts.</p>
    </details>
  </section>
</main>

<script nonce="${nonce}">
(function () {
  "use strict";
  var token = location.hash.slice(1);
  history.replaceState(null, "", location.pathname);
  var state = null;
  // Cards are rebuilt on every refresh; a flash carries a result message across.
  var flash = null;

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") node.textContent = attrs[k];
      else if (k === "className") node.className = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function api(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + token },
      body: JSON.stringify(body || {})
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) throw new Error(data.error || ("Request failed (" + res.status + ")"));
        return data;
      });
    });
  }

  function say(node, kind, text) { node.className = "result " + kind; node.textContent = text; }

  function busy(button, fn) {
    button.disabled = true;
    return fn().finally(function () { button.disabled = false; });
  }

  var KIND_LABEL = { bearer: "Bearer token", header: "Header", basic: "Basic auth", query: "URL parameter" };
  var SOURCE_LABEL = { keychain: "Key saved", env: "Key from environment", missing: "No key yet" };

  function explainStatus(status) {
    if (status >= 200 && status < 300) return ["ok", "Works (" + status + ")."];
    if (status === 401 || status === 403) return ["bad", "Rejected (" + status + "). The key is wrong, expired, or lacks this permission."];
    if (status === 404) return ["warn", "404 at that path. The key may be fine; try a real endpoint path."];
    if (status >= 300 && status < 400) return ["warn", "Redirect (" + status + "). Check the base URL."];
    if (status === 0) return ["bad", "Could not reach the API."];
    return ["warn", "Got " + status + ". Check the path or the API's docs."];
  }

  function renderCard(c) {
    var result = el("div", { className: "result" });
    if (flash && flash.id === c.id) { say(result, flash.kind, flash.text); flash = null; }
    var input = el("input", { type: "password", placeholder: c.source === "missing" ? "Paste key" : "Paste a new key to replace it", spellcheck: "false", autocomplete: "off" });
    var save = el("button", { className: "primary", text: c.source === "missing" ? "Save key" : "Replace" });
    var testPath = el("input", { placeholder: "Test path, e.g. /models (optional)", spellcheck: "false" });
    var test = el("button", { text: "Test" });
    var remove = el("button", { className: "ghost", text: "Remove key" });

    save.addEventListener("click", function () {
      busy(save, function () {
        return api("/api/secret", { credentialId: c.id, value: input.value })
          .then(function () { input.value = ""; flash = { id: c.id, kind: "ok", text: "Saved. Restart Claude Code to pick it up." }; return refresh(); })
          .catch(function (e) { say(result, "bad", e.message); });
      });
    });
    input.addEventListener("keydown", function (e) { if (e.key === "Enter") save.click(); });
    test.addEventListener("click", function () {
      busy(test, function () {
        return api("/api/test", { credentialId: c.id, path: testPath.value })
          .then(function (r) { var x = explainStatus(r.status); say(result, x[0], x[1]); })
          .catch(function (e) { say(result, "bad", e.message); });
      });
    });
    remove.addEventListener("click", function () {
      if (!confirm("Remove the saved key for " + c.id + "? The API stays in the policy.")) return;
      busy(remove, function () {
        return api("/api/secret/delete", { credentialId: c.id })
          .then(function () { flash = { id: c.id, kind: "ok", text: "Key removed." }; return refresh(); })
          .catch(function (e) { say(result, "bad", e.message); });
      });
    });

    var meta = c.baseUrl + " · " + KIND_LABEL[c.kind] + (c.paramName ? " (" + c.paramName + ")" : "") +
      " · " + (c.grantedTo.length ? "used by " + c.grantedTo.join(", ") : "no agent has access");
    var envNote = c.source === "env"
      ? el("p", { className: "hint", text: "Set by " + c.envVar + " in the environment or .env, which overrides a saved key." })
      : c.note ? el("p", { className: "hint", text: c.note }) : null;

    return el("div", { className: "card" }, [
      el("div", { className: "card-top" }, [
        el("div", {}, [el("div", { className: "name", text: c.id }), el("div", { className: "meta", text: (c.description ? c.description + " · " : "") + meta })]),
        el("span", { className: "pill " + c.source, text: SOURCE_LABEL[c.source] })
      ]),
      envNote,
      el("div", { className: "row" }, [input, save]),
      el("div", { className: "row" }, [testPath, test, c.source === "keychain" ? remove : null]),
      result
    ]);
  }

  function renderStoredOnly(k) {
    var result = el("div", { className: "result" });
    if (flash && flash.id === k.id) { say(result, flash.kind, flash.text); flash = null; }
    var input = el("input", { type: "password", placeholder: "Paste a new key to replace it", spellcheck: "false", autocomplete: "off" });
    var save = el("button", { text: "Replace" });
    var connect = el("button", { text: "Connect to an API" });
    var remove = el("button", { className: "ghost", text: "Remove key" });
    save.addEventListener("click", function () {
      busy(save, function () {
        return api("/api/secret", { credentialId: k.id, value: input.value })
          .then(function () { input.value = ""; flash = { id: k.id, kind: "ok", text: "Replaced." }; return refresh(); })
          .catch(function (e) { say(result, "bad", e.message); });
      });
    });
    connect.addEventListener("click", function () {
      form.id.value = k.id;
      form.value.value = "";
      form.baseUrl.focus();
      form.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    remove.addEventListener("click", function () {
      if (!confirm("Remove the stored key " + k.id + " from Credential Manager?")) return;
      busy(remove, function () {
        return api("/api/secret/delete", { credentialId: k.id })
          .then(function () { return refresh(); })
          .catch(function (e) { say(result, "bad", e.message); });
      });
    });
    return el("div", { className: "card" }, [
      el("div", { className: "card-top" }, [
        el("div", {}, [el("div", { className: "name", text: k.id }), k.note ? el("div", { className: "meta", text: k.note }) : null]),
        el("span", { className: "pill keychain", text: "Stored" })
      ]),
      el("div", { className: "row" }, [input, save, connect, remove]),
      result
    ]);
  }

  function render() {
    var where = document.getElementById("where");
    where.textContent = state.policyFile + (state.keychain ? " · keys in " + state.keychain : "");

    var banner = document.getElementById("banner");
    banner.innerHTML = "";
    if (state.policyError) banner.appendChild(el("div", { className: "banner bad", text: "Policy file has a problem: " + state.policyError }));
    else if (!state.keychain) banner.appendChild(el("div", { className: "banner warn", text: "No keychain on this platform. Keys must be set as environment variables." }));

    var list = document.getElementById("list");
    list.innerHTML = "";
    if (!state.credentials.length) {
      list.appendChild(el("p", { className: "empty", text: state.policyExists ? "No APIs in the policy." : "No APIs yet. Add your first one below." }));
    }
    state.credentials.forEach(function (c) { list.appendChild(renderCard(c)); });

    var storedOnly = document.getElementById("storedOnly");
    storedOnly.innerHTML = "";
    if (state.storedOnly.length) {
      storedOnly.appendChild(el("h3", { text: "Stored only (" + state.storedOnly.length + ")" }));
      storedOnly.appendChild(el("p", { className: "hint", text: "Housed in Credential Manager but not connected to an API, so no agent can use them. To connect one, use Add an API with the same short name and leave the key field empty." }));
      state.storedOnly.forEach(function (k) { storedOnly.appendChild(renderStoredOnly(k)); });
    }

    var importAgent = document.getElementById("importAgent");
    var prevImport = importAgent.value;
    importAgent.innerHTML = "";
    state.agents.forEach(function (a) { importAgent.appendChild(el("option", { value: a.id, text: a.id })); });
    importAgent.appendChild(el("option", { value: "__new", text: "New agent…" }));
    importAgent.appendChild(el("option", { value: "__none", text: "Nobody yet" }));
    importAgent.value = prevImport && importAgent.querySelector("option[value='" + prevImport + "']") ? prevImport : (state.agents.length ? state.agents[0].id : "__new");
    syncImportAgent();

    var agentSelect = document.querySelector("#add select[name=agent]");
    var previous = agentSelect.value;
    agentSelect.innerHTML = "";
    state.agents.forEach(function (a) { agentSelect.appendChild(el("option", { value: a.id, text: a.displayName && a.displayName !== a.id ? a.displayName + " (" + a.id + ")" : a.id })); });
    agentSelect.appendChild(el("option", { value: "__new", text: "New agent…" }));
    if (state.agents.length) agentSelect.appendChild(el("option", { value: "__none", text: "Nobody yet (edit the policy by hand)" }));
    agentSelect.value = previous && agentSelect.querySelector("option[value='" + previous + "']") ? previous : (state.agents.length ? state.agents[0].id : "__new");
    syncAgent();

    var connectAgent = document.getElementById("connectAgent");
    var prevConnect = connectAgent.value;
    connectAgent.innerHTML = "";
    state.agents.forEach(function (a) { connectAgent.appendChild(el("option", { value: a.id, text: a.id })); });
    if (prevConnect) connectAgent.value = prevConnect;
    renderConnect();
  }

  function q(s) { return '"' + s + '"'; }
  function renderConnect() {
    var agent = document.getElementById("connectAgent").value;
    var r = state.register;
    var cmd = agent
      ? "claude mcp add credential-broker --scope user" +
        " -e BROKER_AGENT_ID=" + agent +
        " -e BROKER_POLICY_FILE=" + q(r.policyFile) +
        " -e BROKER_AUDIT_FILE=" + q(r.auditFile) +
        " -e BROKER_APPROVALS_FILE=" + q(r.approvalsFile) +
        " -- node " + q(r.stdioEntry)
      : "Add an API with an agent first.";
    document.getElementById("connectCmd").textContent = cmd;
  }

  function refresh() {
    return api("/api/state").then(function (s) { state = s; render(); })
      .catch(function (e) {
        var banner = document.getElementById("banner");
        banner.innerHTML = "";
        banner.appendChild(el("div", { className: "banner bad", text: e.message }));
      });
  }

  var form = document.getElementById("add");
  function syncKind() {
    var kind = form.kind.value;
    document.getElementById("paramWrap").classList.toggle("hidden", kind !== "header" && kind !== "query");
    document.getElementById("paramLabel").textContent = kind === "query" ? "Parameter name" : "Header name";
    form.paramName.placeholder = kind === "query" ? "api_key" : "x-api-key";
    document.getElementById("queryRisk").classList.toggle("hidden", kind !== "query");
  }
  function syncAgent() {
    document.getElementById("newAgentWrap").classList.toggle("hidden", form.agent.value !== "__new");
  }
  form.kind.addEventListener("change", syncKind);
  form.agent.addEventListener("change", syncAgent);
  syncKind();

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var result = document.getElementById("addResult");
    var agentChoice = form.agent.value;
    var grant = null;
    if (agentChoice !== "__none") {
      var agentId = agentChoice === "__new" ? (form.newAgent.value.trim() || "claude") : agentChoice;
      grant = {
        agentId: agentId,
        queryParams: form.queryParams.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean)
      };
    }
    var body = {
      id: form.id.value.trim(),
      description: form.description.value.trim(),
      baseUrl: form.baseUrl.value.trim(),
      kind: form.kind.value,
      acknowledgeQueryRisk: form.acknowledgeQueryRisk.checked,
      value: form.value.value,
      grant: grant
    };
    if (form.paramName.value.trim() && (body.kind === "header" || body.kind === "query")) body.paramName = form.paramName.value.trim();
    var button = form.querySelector("button[type=submit]");
    busy(button, function () {
      return api("/api/credential", body).then(function () {
        say(result, "ok", "Added " + body.id + (body.value ? " with its key." : ". Paste its key in the card above.") + " Restart Claude Code to pick it up.");
        form.reset(); syncKind();
        return refresh();
      }).catch(function (err) { say(result, "bad", err.message); });
    });
  });

  document.getElementById("connectAgent").addEventListener("change", renderConnect);
  document.getElementById("copyCmd").addEventListener("click", function (e) {
    navigator.clipboard.writeText(document.getElementById("connectCmd").textContent).then(function () {
      e.target.textContent = "Copied"; setTimeout(function () { e.target.textContent = "Copy"; }, 1500);
    });
  });
  document.getElementById("close").addEventListener("click", function () {
    api("/api/close").finally(function () {
      document.body.innerHTML = "";
      document.body.appendChild(el("main", {}, [el("h1", { text: "Key manager closed." }), el("p", { className: "sub", text: "Run npm run keys to open it again." })]));
    });
  });

  // ---- Import ----------------------------------------------------------
  var scanRows = [];
  function syncImportAgent() {
    document.getElementById("importNewAgent").classList.toggle("hidden", document.getElementById("importAgent").value !== "__new");
  }
  document.getElementById("importAgent").addEventListener("change", syncImportAgent);

  function renderImportRows() {
    var holder = document.getElementById("importRows");
    holder.innerHTML = "";
    if (!scanRows.length) {
      holder.appendChild(el("p", { className: "empty", text: "No keys found in the usual places." }));
      return;
    }
    scanRows.forEach(function (r) {
      var check = el("input", { type: "checkbox" });
      check.checked = !r.alreadyStoredAs && !r.sensitive;
      var idInput = el("input", { type: "text", value: r.suggestedId, spellcheck: "false", "aria-label": "Short name for " + r.name });
      var mode = el("select", { "aria-label": "What to do with " + r.name });
      if (r.preset) mode.appendChild(el("option", { value: "api", text: "Add as " + r.preset.label + " API" }));
      mode.appendChild(el("option", { value: "store", text: "Store only" }));
      var where = r.sources.map(function (s) { return s.where + (s.path ? ": " + s.path : ""); }).join(" · ");
      var flag = null;
      if (r.sensitive) flag = el("div", { className: "flag warn", text: "Looks like a wallet key. Store only; never give an agent this." });
      else if (r.alreadyStoredAs) flag = el("div", { className: "flag ok", text: "Already saved as " + r.alreadyStoredAs });
      else if (r.idTaken) flag = el("div", { className: "flag warn", text: "That short name is taken; change it before importing." });
      var status = el("div", { className: "flag" });
      r.ui = { check: check, idInput: idInput, mode: mode, status: status };
      holder.appendChild(el("div", { className: "irow" }, [
        check,
        el("div", {}, [el("div", { className: "name", text: r.name }), el("div", { className: "src", text: where }), flag, status]),
        idInput,
        mode
      ]));
    });
  }

  document.getElementById("scan").addEventListener("click", function (e) {
    var button = e.target;
    var result = document.getElementById("importResult");
    button.textContent = "Searching… (about 10 seconds)";
    busy(button, function () {
      return api("/api/import/scan").then(function (data) {
        scanRows = data.rows;
        document.getElementById("importArea").classList.remove("hidden");
        say(result, "", "");
        renderImportRows();
      }).catch(function (err) { say(result, "bad", err.message); })
        .finally(function () { button.textContent = "Search again"; });
    });
  });

  document.getElementById("importGo").addEventListener("click", function (e) {
    var result = document.getElementById("importResult");
    var picked = scanRows.filter(function (r) { return r.ui.check.checked; });
    if (!picked.length) { say(result, "warn", "Tick at least one key."); return; }
    var agentChoice = document.getElementById("importAgent").value;
    var agentId = agentChoice === "__none" ? null : agentChoice === "__new" ? (document.getElementById("importNewAgent").value.trim() || "claude") : agentChoice;
    var body = {
      agentId: agentId,
      items: picked.map(function (r) { return { rowId: r.rowId, id: r.ui.idInput.value.trim(), mode: r.ui.mode.value }; })
    };
    busy(e.target, function () {
      return api("/api/import/apply", body).then(function (data) {
        var ok = 0;
        data.results.forEach(function (res) {
          var row = scanRows.find(function (r) { return r.rowId === res.rowId; });
          if (!row) return;
          var text = res.message;
          var kind = res.ok ? "ok" : "bad";
          if (res.test) {
            var x = explainStatus(res.test.status);
            text += " Test " + res.test.path + ": " + x[1];
            if (x[0] !== "ok") kind = "warn";
          }
          if (res.ok) { ok += 1; row.ui.check.checked = false; }
          row.ui.status.className = "flag " + kind;
          row.ui.status.textContent = text;
        });
        say(result, ok === data.results.length ? "ok" : "warn",
          ok + " of " + data.results.length + " imported. The original copies are untouched; delete them yourself once you are happy. Restart Claude Code so the broker loads the new keys.");
        return refresh();
      }).catch(function (err) { say(result, "bad", err.message); });
    });
  });

  if (!token) {
    document.getElementById("banner").appendChild(el("div", { className: "banner bad", text: "Missing session token. Open the link printed by npm run keys." }));
  } else {
    refresh();
  }
})();
</script>
</body>
</html>`;
}
