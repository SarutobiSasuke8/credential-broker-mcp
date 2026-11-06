/**
 * The key manager page. Self-contained: no external scripts, styles, or
 * fonts, so the strict CSP in keys-ui.ts holds. The session token arrives in
 * the URL fragment and is moved into memory, then wiped from the address bar.
 *
 * Layout, top to bottom: summary, Add a key, Your keys (search, filter,
 * expiry and notes), then Import and Connect as collapsed sections.
 * Written without backticks or template placeholders inside the page code,
 * because the whole page is one TypeScript template literal.
 */
export function renderKeysPage(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Credential Broker: Keys</title>
<style nonce="${nonce}">
:root {
  color-scheme: light dark;
  --bg: #f4f5f7; --panel: #ffffff; --ink: #14171c; --muted: #5d6573; --line: #dfe3ea; --line-strong: #c9cfd9;
  --accent: #0f6b62; --accent-hover: #0b574f; --accent-ink: #ffffff; --accent-soft: #e2f3f0;
  --ok: #1f7a46; --ok-bg: #e3f4ea; --warn: #8f5600; --warn-bg: #fdf1d9; --bad: #a42c2c; --bad-bg: #fce8e8;
  --field: #fbfcfd; --shadow: 0 1px 2px rgba(16, 24, 40, 0.06), 0 1px 3px rgba(16, 24, 40, 0.04);
  --radius: 12px; --radius-sm: 8px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1114; --panel: #171a1f; --ink: #eceef2; --muted: #9aa3b2; --line: #272c34; --line-strong: #353c47;
    --accent: #4fc4b5; --accent-hover: #6fd3c6; --accent-ink: #07211d; --accent-soft: #14302c;
    --ok: #7fd49c; --ok-bg: #16301f; --warn: #f0bc63; --warn-bg: #352a12; --bad: #f59a9a; --bad-bg: #3a1c1c;
    --field: #12151a; --shadow: none;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; -webkit-font-smoothing: antialiased; }
main { max-width: 1040px; margin: 0 auto; padding: 24px 20px 72px; }
h1 { font-size: 20px; margin: 0; letter-spacing: -0.015em; }
h2 { font-size: 17px; margin: 0; letter-spacing: -0.01em; }
h3 { font-size: 13px; margin: 22px 0 4px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.sub { color: var(--muted); font-size: 12.5px; margin: 2px 0 0; word-break: break-all; }
.lede { color: var(--muted); font-size: 14px; margin: 4px 0 0; }
.top { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 20px; }
.brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
.logo { width: 38px; height: 38px; border-radius: 10px; background: var(--accent); color: var(--accent-ink); display: grid; place-items: center; flex: none; }
.logo svg { width: 20px; height: 20px; }
.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
.stat { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 14px 16px; box-shadow: var(--shadow); }
.stat .n { font-size: 26px; font-weight: 650; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; line-height: 1.1; }
.stat .l { color: var(--muted); font-size: 12.5px; margin-top: 2px; }
.stat.warn .n { color: var(--warn); } .stat.bad .n { color: var(--bad); }
.panel, section { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 20px; margin-bottom: 16px; box-shadow: var(--shadow); }
.panel.primary { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft), var(--shadow); }
.section-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
.tools { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.tools input[type=search] { width: 220px; }
.chips { display: inline-flex; border: 1px solid var(--line-strong); border-radius: 999px; overflow: hidden; }
.chip { border: 0; border-radius: 0; background: transparent; padding: 6px 12px; font-size: 13px; font-weight: 550; color: var(--muted); }
.chip[aria-pressed=true] { background: var(--accent-soft); color: var(--accent); }
.card { border: 1px solid var(--line); border-radius: var(--radius); margin-top: 12px; background: var(--panel); }
.card.attention { border-color: var(--warn); } .card.expired { border-color: var(--bad); }
.card-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; flex-wrap: wrap; padding: 14px 16px 10px; }
.name { font-weight: 650; font-size: 15.5px; }
.meta { color: var(--muted); font-size: 13px; margin-top: 2px; word-break: break-all; }
.pills { display: flex; gap: 6px; flex-wrap: wrap; }
.pill { font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 999px; white-space: nowrap; background: var(--field); color: var(--muted); border: 1px solid var(--line); }
.pill.keychain, .pill.env, .pill.ok { background: var(--ok-bg); color: var(--ok); border-color: transparent; }
.pill.missing, .pill.soon { background: var(--warn-bg); color: var(--warn); border-color: transparent; }
.pill.expired { background: var(--bad-bg); color: var(--bad); border-color: transparent; }
.usernote { margin: 0 16px 10px; font-size: 13.5px; color: var(--ink); background: var(--field); border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 8px 10px; }
.manage { border-top: 1px solid var(--line); }
.manage > summary { cursor: pointer; padding: 10px 16px; font-size: 13.5px; font-weight: 600; color: var(--accent); list-style: none; }
.manage > summary::-webkit-details-marker { display: none; }
.manage > summary::before { content: "\\25B8"; display: inline-block; width: 1.1em; transition: transform 0.12s; }
.manage[open] > summary::before { transform: rotate(90deg); }
.manage-body { padding: 0 16px 16px; }
.row { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; align-items: center; }
.row > input[type=password], .row > input[type=text] { flex: 1 1 240px; }
.block-label { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 14px 0 0; }
input, select, textarea { font: inherit; color: inherit; background: var(--field); border: 1px solid var(--line-strong); border-radius: var(--radius-sm); padding: 9px 11px; min-width: 0; }
textarea { resize: vertical; min-height: 64px; width: 100%; }
input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
button { font: inherit; font-weight: 600; font-size: 14px; border-radius: var(--radius-sm); padding: 8px 14px; cursor: pointer; border: 1px solid var(--line-strong); background: var(--panel); color: var(--ink); }
button:hover { border-color: var(--accent); }
button.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
button.primary:hover { background: var(--accent-hover); }
button.ghost { background: transparent; }
button.danger { color: var(--bad); }
button.small { padding: 4px 10px; font-size: 12.5px; }
button:disabled { opacity: 0.6; cursor: progress; }
.result { font-size: 13px; margin-top: 8px; }
.result.ok { color: var(--ok); } .result.bad { color: var(--bad); } .result.warn { color: var(--warn); }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 16px; margin-top: 16px; }
.grid label, .field { display: flex; flex-direction: column; gap: 5px; font-size: 13px; font-weight: 600; color: var(--muted); }
.grid .full { grid-column: 1 / -1; }
.grid label input, .grid label select, .field input, .field select { color: var(--ink); font-size: 15px; font-weight: 400; }
.hint { font-size: 12.5px; color: var(--muted); font-weight: 400; }
.choices { display: flex; flex-wrap: wrap; gap: 8px 20px; margin-top: 6px; }
.grid .choices label { display: inline-flex; flex-direction: row; align-items: center; gap: 7px; color: var(--ink); font-weight: 450; font-size: 14px; }
.choices input[type=checkbox], .check input { width: auto; }
.check { display: flex; gap: 8px; align-items: flex-start; font-size: 13px; color: var(--muted); font-weight: 400; flex-direction: row !important; }
.quick { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
.advanced { grid-column: 1 / -1; border: 1px dashed var(--line-strong); border-radius: var(--radius-sm); padding: 10px 12px; }
.advanced > summary { cursor: pointer; font-size: 13.5px; font-weight: 600; color: var(--muted); }
.advanced .grid { margin-top: 12px; }
.banner { padding: 12px 16px; border-radius: var(--radius); margin-bottom: 16px; font-size: 14px; }
.banner.bad { background: var(--bad-bg); color: var(--bad); }
.banner.warn { background: var(--warn-bg); color: var(--warn); }
.banner ul { margin: 6px 0 0; padding-left: 18px; }
.empty { color: var(--muted); font-size: 14px; padding: 18px 0 4px; }
pre { background: var(--field); border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 12px; overflow-x: auto; font-size: 12.5px; margin: 8px 0; white-space: pre-wrap; word-break: break-all; }
details.panel > summary { cursor: pointer; font-weight: 650; font-size: 16px; }
.hidden { display: none !important; }
.irow { display: grid; grid-template-columns: auto 1fr 200px 200px; gap: 10px; align-items: center; padding: 10px 0; border-top: 1px solid var(--line); }
.irow:first-child { border-top: 0; }
.irow .src { font-size: 12px; color: var(--muted); word-break: break-all; }
.irow .flag { font-size: 12px; font-weight: 600; }
.irow .flag.warn { color: var(--warn); } .irow .flag.ok { color: var(--ok); } .irow .flag.bad { color: var(--bad); }
.irow input[type=text] { width: 100%; }
.import-controls select { margin-left: 6px; }
button.panic { background: var(--bad); color: #ffffff; border-color: var(--bad); }
button.panic:hover { filter: brightness(1.1); border-color: var(--bad); }
button.resume { background: var(--ok); color: #ffffff; border-color: var(--ok); }
.pill.paused { background: var(--bad-bg); color: var(--bad); border-color: transparent; }
.banner.pause { background: var(--bad-bg); color: var(--bad); border: 1px solid var(--bad); }
.banner.pause .row { margin-top: 8px; }
.usage { margin: 0 16px 10px; font-size: 13px; color: var(--muted); }
.usage strong { color: var(--ink); font-weight: 600; }
.agent-row, .appr-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; padding: 10px 0; border-top: 1px solid var(--line); }
.agent-row:first-child, .appr-row:first-child { border-top: 0; }
.appr-id { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12.5px; word-break: break-all; }
.linkout { font-size: 13px; color: var(--accent); }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.backdrop { position: fixed; inset: 0; background: rgba(10, 12, 16, 0.55); display: grid; place-items: center; padding: 20px; z-index: 50; }
.modal { background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: 0 20px 50px rgba(0, 0, 0, 0.35); width: min(520px, 100%); padding: 22px 24px; }
.modal h2 { font-size: 18px; margin: 0 0 8px; }
.modal p { margin: 0 0 10px; font-size: 14.5px; }
.modal .facts { display: flex; gap: 8px; flex-wrap: wrap; margin: 4px 0 12px; }
.modal .facts .pill { font-size: 13px; }
.modal label { display: flex; flex-direction: column; gap: 6px; font-size: 13px; font-weight: 600; color: var(--muted); margin-top: 10px; }
.modal label input { font-size: 16px; letter-spacing: 0.08em; font-weight: 600; color: var(--ink); text-transform: uppercase; }
.modal .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
.modal.danger h2 { color: var(--bad); }
.toasts { position: fixed; left: 50%; bottom: 20px; transform: translateX(-50%); display: flex; flex-direction: column; gap: 8px; z-index: 60; width: min(560px, calc(100% - 32px)); }
.toast { background: var(--ink); color: var(--bg); border-radius: var(--radius-sm); padding: 12px 14px; display: flex; align-items: center; gap: 12px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25); font-size: 14px; animation: rise 0.16s ease-out; }
.toast .grow { flex: 1; }
.toast button { background: transparent; color: inherit; border-color: rgba(255, 255, 255, 0.35); padding: 5px 12px; font-size: 13px; }
.toast button:hover { border-color: currentColor; }
.toast .count { font-variant-numeric: tabular-nums; opacity: 0.75; font-size: 12.5px; }
@keyframes rise { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .toast { animation: none; } .manage > summary::before { transition: none; } }
@media (max-width: 760px) {
  .stats { grid-template-columns: repeat(2, 1fr); }
  .grid { grid-template-columns: 1fr; }
  .irow { grid-template-columns: auto 1fr; } .irow > :nth-child(3), .irow > :nth-child(4) { grid-column: 2; }
  .tools input[type=search] { width: 100%; }
}
</style>
</head>
<body>
<main>
  <header class="top">
    <div class="brand">
      <div class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-4 4 3 3m-6-1 2 2"/></svg></div>
      <div>
        <h1>Credential Broker</h1>
        <p class="sub" id="where">Loading…</p>
      </div>
    </div>
    <div class="tools">
      <button class="panic" id="panic" title="Stops every agent request on its next call. Nothing is deleted. Asks you to type PAUSE.">Pause all access</button>
      <button class="ghost" id="close">Close</button>
    </div>
  </header>

  <div id="pauseBanner"></div>
  <div id="requestBanner"></div>
  <div id="banner"></div>
  <div class="stats" id="stats"></div>

  <section class="panel primary" id="addPanel">
    <h2>Add a key</h2>
    <p class="lede">The key goes straight into Windows Credential Manager. Agents can use it through the broker but never see it, and this page never shows it back.</p>
    <form id="add" class="grid" autocomplete="off">
      <label>Short name
        <input name="id" placeholder="openai" required pattern="[a-z0-9][a-z0-9._-]{1,63}">
        <span class="hint">Lowercase letters, digits, dots and dashes. The agent picks the key by this name.</span>
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
      <label class="check hidden full" id="queryRisk"><input type="checkbox" name="acknowledgeQueryRisk">
        <span>I understand keys in URLs often end up in server and proxy logs. Prefer a header if the API supports one.</span>
      </label>
      <label class="full">API key
        <input name="value" type="password" placeholder="Paste the key" spellcheck="false">
        <span class="hint">Stored in Windows Credential Manager under credential-broker/&lt;short name&gt;.</span>
      </label>
      <div class="field">Expires
        <input name="expires" type="date">
        <span class="quick" id="expiryQuick"></span>
      </div>
      <label>Notes
        <textarea name="userNote" maxlength="500" placeholder="Where it was created, what it is for, how to rotate it"></textarea>
      </label>
      <div class="full">Who can use it
        <div id="grantChoices" class="choices"></div>
        <span class="hint">Read access only (GET). A selected group stays assigned as its membership changes. Individual selections are separate read grants.</span>
      </div>
      <details class="advanced">
        <summary>More options</summary>
        <div class="grid">
          <label class="check full"><input id="newAgentToggle" type="checkbox"> Add a new agent</label>
          <label id="newAgentWrap" class="hidden">New agent name
            <input name="newAgent" placeholder="claude" pattern="[a-z0-9][a-z0-9._-]{1,63}">
          </label>
          <label class="full">Query parameters the agent may use (optional)
            <input name="queryParams" placeholder="q, limit, page">
            <span class="hint">Any query parameter not listed is refused. Write access (POST, DELETE…) stays a hand-written policy decision.</span>
          </label>
        </div>
      </details>
      <div class="full">
        <button class="primary" type="submit">Add key</button>
        <div class="result" id="addResult" role="status"></div>
      </div>
    </form>
  </section>

  <section id="keysSection">
    <div class="section-head">
      <h2>Your keys</h2>
      <div class="tools">
        <input type="search" id="search" placeholder="Search keys" aria-label="Search keys">
        <div class="chips" role="group" aria-label="Filter keys">
          <button class="chip" data-filter="all" aria-pressed="true">All</button>
          <button class="chip" data-filter="attention" aria-pressed="false">Needs attention</button>
          <button class="chip" data-filter="nokey" aria-pressed="false">No key yet</button>
        </div>
      </div>
    </div>
    <div id="list"><p class="empty">Loading…</p></div>
    <div id="storedOnly"></div>
  </section>

  <section id="accessSection">
    <div class="section-head"><h2>Agents</h2></div>
    <p class="hint">Pause one agent without touching the others. A pause takes effect on the agent's next request and needs no restart. Nothing is deleted, and resuming restores exactly what was there. Every pause and resume is written to the audit log.</p>
    <div id="agentList"></div>
  </section>

  <details class="panel" id="approvalsPanel">
    <summary>Approvals for state-changing requests</summary>
    <p class="hint">Operations the policy marks as needing approval stay blocked until you create an approval here and give its id to the agent. Approvals expire on their own and can be revoked at any time.</p>
    <div id="approvalCreate"></div>
    <div id="approvalList"></div>
  </details>

  <details class="panel" id="importPanel">
    <summary>Import keys already on this computer</summary>
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
  </details>

  <details class="panel" id="connect">
    <summary>Connect to Claude Code</summary>
    <p class="hint">Run once per agent identity. The broker reads keys from Credential Manager at start-up, so nothing secret goes in this command.</p>
    <label class="hint">Agent <select id="connectAgent"></select></label>
    <pre id="connectCmd"></pre>
    <button id="copyCmd">Copy</button>
    <p class="hint">Restart Claude Code after adding or changing a key: the broker loads keys once when it starts.</p>
  </details>
</main>
<div id="modalHost"></div>
<div class="toasts" id="toasts"></div>
<div class="sr-only" id="live" aria-live="assertive" role="status"></div>

<script nonce="${nonce}">
(function () {
  "use strict";
  // The fragment is "<token>" or "<token>.<request>". The request is an agent's
  // key request, pre-validated by the server; it is only ever shown as text.
  var hashParts = location.hash.slice(1).split(".");
  var token = hashParts[0];
  var prefill = null;
  if (hashParts[1]) {
    try {
      var bin = atob(hashParts[1].replace(/-/g, "+").replace(/_/g, "/"));
      var bytes = new Uint8Array(bin.length);
      for (var bi = 0; bi < bin.length; bi++) bytes[bi] = bin.charCodeAt(bi);
      prefill = JSON.parse(new TextDecoder().decode(bytes));
    } catch (ignore) { prefill = null; }
  }
  history.replaceState(null, "", location.pathname);
  var state = null;
  var filter = "all";
  var search = "";
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

  function announce(text) {
    var live = document.getElementById("live");
    live.textContent = "";
    setTimeout(function () { live.textContent = text; }, 30);
  }

  // A small dialog. Resolves true on confirm, false on cancel or Esc. With
  // opts.word set, the confirm button stays disabled until that word is typed
  // (case-insensitive, trimmed), Enter confirms once it matches, and focus
  // starts in the field. Focus is trapped inside and restored afterwards.
  function openModal(opts) {
    return new Promise(function (resolveModal) {
      var host = document.getElementById("modalHost");
      var previous = document.activeElement;
      var field = null;
      var confirmBtn = el("button", { type: "button", className: opts.danger ? "panic" : "primary", text: opts.confirmLabel || "Confirm" });
      var cancelBtn = el("button", { type: "button", className: "ghost", text: "Cancel" });
      var body = el("div", {}, opts.body || []);
      if (opts.word) {
        field = el("input", { type: "text", autocomplete: "off", spellcheck: "false", autocapitalize: "characters", placeholder: opts.word, "aria-describedby": "modalWhy" });
        body.appendChild(el("label", { text: "Type " + opts.word + " to confirm" }, [field]));
        confirmBtn.disabled = true;
      }
      var box = el("div", { className: "modal" + (opts.danger ? " danger" : ""), role: "dialog", "aria-modal": "true", "aria-labelledby": "modalTitle" }, [
        el("h2", { id: "modalTitle", text: opts.title }),
        body,
        el("div", { className: "actions" }, [cancelBtn, confirmBtn])
      ]);
      var backdrop = el("div", { className: "backdrop" }, [box]);
      function matches() { return !opts.word || field.value.trim().toUpperCase() === opts.word; }
      function close(result) {
        document.removeEventListener("keydown", onKey, true);
        backdrop.remove();
        if (previous && previous.focus) previous.focus();
        resolveModal(result);
      }
      function onKey(e) {
        if (e.key === "Escape") { e.preventDefault(); close(false); return; }
        if (e.key === "Enter" && !(e.target && e.target.tagName === "BUTTON")) { e.preventDefault(); if (matches()) close(true); return; }
        if (e.key === "Tab") {
          var focusable = Array.from(box.querySelectorAll("input, button")).filter(function (n) { return !n.disabled; });
          var first = focusable[0], last = focusable[focusable.length - 1];
          if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
          else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      }
      if (field) field.addEventListener("input", function () { confirmBtn.disabled = !matches(); });
      confirmBtn.addEventListener("click", function () { if (matches()) close(true); });
      cancelBtn.addEventListener("click", function () { close(false); });
      backdrop.addEventListener("mousedown", function (e) { if (e.target === backdrop) close(false); });
      document.addEventListener("keydown", onKey, true);
      host.replaceChildren(backdrop);
      (field || cancelBtn).focus();
    });
  }

  // A short message at the bottom of the page. With opts.undo, an Undo button
  // and a countdown stay for opts.seconds (default 8); the undo runs at most once.
  function toast(text, opts) {
    opts = opts || {};
    var host = document.getElementById("toasts");
    var seconds = opts.seconds || (opts.undo ? 8 : 4);
    var left = seconds;
    var done = false;
    var count = el("span", { className: "count", text: String(left) + "s" });
    var node = el("div", { className: "toast", role: "status" }, [el("span", { className: "grow", text: text })]);
    function finish() {
      if (done) return;
      done = true;
      clearInterval(timer);
      node.remove();
    }
    if (opts.undo) {
      var undoBtn = el("button", { type: "button", text: "Undo" });
      undoBtn.addEventListener("click", function () {
        if (done) return;
        finish();
        opts.undo();
      });
      node.appendChild(count);
      node.appendChild(undoBtn);
    }
    var timer = setInterval(function () {
      left -= 1;
      count.textContent = String(left) + "s";
      if (left <= 0) finish();
    }, 1000);
    host.appendChild(node);
    announce(text);
    return { close: finish };
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

  function expiryPill(c) {
    var d = c.expiryDays;
    if (c.expiryState === "none") return { kind: "none", text: "No expiry set" };
    if (c.expiryState === "expired") return { kind: "expired", text: d === -1 ? "Expired yesterday" : "Expired " + (-d) + " days ago" };
    if (d === 0) return { kind: "soon", text: "Expires today" };
    if (c.expiryState === "soon") return { kind: "soon", text: d === 1 ? "Expires tomorrow" : "Expires in " + d + " days" };
    return { kind: "ok", text: "Expires " + c.expires };
  }

  function needsAttention(c) { return c.expiryState === "expired" || c.expiryState === "soon"; }

  function ago(iso) {
    var ms = Date.now() - Date.parse(iso);
    if (isNaN(ms)) return "";
    var mins = Math.round(ms / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + " min ago";
    var hours = Math.round(mins / 60);
    if (hours < 48) return hours + (hours === 1 ? " hour ago" : " hours ago");
    var days = Math.round(hours / 24);
    return days + " days ago";
  }

  function usageLine(c) {
    var parts = [];
    var u = c.usage;
    if (u && u.lastAt) {
      parts.push(el("span", {}, [document.createTextNode("Last used "), el("strong", { text: ago(u.lastAt) }), document.createTextNode(u.lastAgent ? " by " + u.lastAgent : "")]));
      parts.push(document.createTextNode(" · last " + state.usageWindowDays + " days: " + u.succeeded + " succeeded, " + u.denied + " denied, " + u.failed + " failed"));
    } else {
      parts.push(document.createTextNode("Not used by any agent yet"));
    }
    if (c.rotatedAt) parts.push(document.createTextNode(" · key replaced " + ago(c.rotatedAt)));
    return el("div", { className: "usage" }, parts);
  }

  function setPause(scope, active, extra) {
    var body = { scope: scope, active: active, reason: "" };
    if (extra && extra.confirm) body.confirm = extra.confirm;
    if (extra && extra.undo) body.undo = true;
    return api("/api/pause", body).then(function () { return refresh(); });
  }

  function scopeLabel(scope) {
    return scope.kind === "agent" ? "agent " + scope.id : "key " + scope.id;
  }

  // Pausing one agent or key: a plain confirmation, then an eight second Undo.
  // Resuming one: a confirmation. Errors land in the given result node.
  function pauseScope(scope, active, result) {
    var label = scopeLabel(scope);
    var ask = active
      ? openModal({
          title: "Pause " + label + "?",
          danger: true,
          confirmLabel: "Pause",
          body: [el("p", { text: (scope.kind === "agent" ? "Every request from this agent" : "Every request for this key") + " will be refused on its next call. Nothing is deleted, and you can resume at any time." })]
        })
      : openModal({
          title: "Resume " + label + "?",
          confirmLabel: "Resume",
          body: [el("p", { text: "Requests " + (scope.kind === "agent" ? "from this agent" : "for this key") + " will be allowed again, as the policy already permits." })]
        });
    return ask.then(function (yes) {
      if (!yes) return;
      return setPause(scope, active).then(function () {
        if (active) {
          toast("Paused " + label + ".", {
            undo: function () {
              setPause(scope, false, { undo: true })
                .then(function () { toast("Resumed " + label + "."); })
                .catch(function (e) { if (result) say(result, "bad", e.message); else alert(e.message); });
            }
          });
        } else {
          toast("Resumed " + label + ".");
        }
      }).catch(function (e) { if (result) say(result, "bad", e.message); else alert(e.message); });
    });
  }

  // The global switch. Pausing asks for the word PAUSE; resuming asks for
  // RESUME, because resuming is the risky direction. The server checks the
  // word as well, so a stray request cannot flip it either.
  function pauseAll(active) {
    var agents = state.agents.length;
    var keys = state.credentials.length;
    var facts = el("div", { className: "facts" }, [
      el("span", { className: "pill", text: agents + (agents === 1 ? " agent" : " agents") }),
      el("span", { className: "pill", text: keys + (keys === 1 ? " key" : " keys") })
    ]);
    var ask = active
      ? openModal({
          title: "Pause all access?",
          danger: true,
          confirmLabel: "Pause everything",
          word: "PAUSE",
          body: [
            el("p", { id: "modalWhy", text: "Every agent request will be refused on its next call. Nothing is deleted. You can resume at any time." }),
            facts
          ]
        })
      : openModal({
          title: "Resume all access?",
          confirmLabel: "Resume everything",
          word: "RESUME",
          body: [
            el("p", { id: "modalWhy", text: "Every agent that is not paused individually will be allowed to make requests again, as the policy permits." }),
            facts
          ]
        });
    return ask.then(function (yes) {
      if (!yes) return;
      return setPause({ kind: "all" }, active, { confirm: active ? "PAUSE" : "RESUME" })
        .then(function () { toast(active ? "All access is paused." : "All access is live again."); })
        .catch(function (err) { alert(err.message); });
    });
  }

  function rank(c) {
    if (c.expiryState === "expired") return 0;
    if (c.expiryState === "soon") return 1;
    if (c.source === "missing") return 2;
    return 3;
  }

  function isoPlus(days) {
    var d = new Date();
    d.setDate(d.getDate() + days);
    var m = String(d.getMonth() + 1); var day = String(d.getDate());
    return d.getFullYear() + "-" + (m.length < 2 ? "0" + m : m) + "-" + (day.length < 2 ? "0" + day : day);
  }

  function renderCard(c) {
    var result = el("div", { className: "result", role: "status" });
    var hadFlash = flash && flash.id === c.id;
    if (hadFlash) { say(result, flash.kind, flash.text); flash = null; }

    var input = el("input", { type: "password", placeholder: c.source === "missing" ? "Paste key" : "Paste a new key to replace it", spellcheck: "false", autocomplete: "off", "aria-label": "API key for " + c.id });
    var save = el("button", { className: "primary", text: c.source === "missing" ? "Save key" : "Replace key" });
    var testPath = el("input", { type: "text", placeholder: "Test path, e.g. /models (optional)", spellcheck: "false", "aria-label": "Test path for " + c.id });
    var test = el("button", { text: "Test" });
    var remove = el("button", { className: "ghost danger", text: "Remove key" });

    var expires = el("input", { type: "date", "aria-label": "Expiry date for " + c.id });
    expires.value = c.expires || "";
    var note = el("input", { type: "text", maxlength: "500", placeholder: "Notes: where it was created, how to rotate it", "aria-label": "Notes for " + c.id });
    note.value = c.userNote || "";
    var saveMeta = el("button", { text: "Save details" });
    var metaResult = el("div", { className: "result", role: "status" });

    save.addEventListener("click", function () {
      busy(save, function () {
        return api("/api/secret", { credentialId: c.id, value: input.value })
          .then(function () { input.value = ""; flash = { id: c.id, kind: "ok", text: "Saved. Restart Claude Code to pick it up. If this is a new key, update the expiry date below." }; return refresh(); })
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
    saveMeta.addEventListener("click", function () {
      busy(saveMeta, function () {
        return api("/api/meta", { credentialId: c.id, expires: expires.value || null, note: note.value })
          .then(function () { flash = { id: c.id, kind: "ok", text: "Details saved." }; return refresh(); })
          .catch(function (e) { say(metaResult, "bad", e.message); });
      });
    });

    var quick = el("span", { className: "quick" });
    [["30 days", 30], ["90 days", 90], ["1 year", 365]].forEach(function (p) {
      var b = el("button", { type: "button", className: "small ghost", text: p[0] });
      b.addEventListener("click", function () { expires.value = isoPlus(p[1]); });
      quick.appendChild(b);
    });

    var pill = expiryPill(c);
    var meta = c.baseUrl + " · " + KIND_LABEL[c.kind] + (c.paramName ? " (" + c.paramName + ")" : "") +
      " · " + (c.grantedTo.length ? "used by " + c.grantedTo.join(", ") : "no agent has access") +
      (c.grantedGroups.length ? " · groups: " + c.grantedGroups.join(", ") : "");
    var envNote = c.source === "env"
      ? el("p", { className: "hint usernote", text: "Set by " + c.envVar + " in the environment or .env, which overrides a saved key." })
      : c.note ? el("p", { className: "hint usernote", text: c.note }) : null;

    var pauseBtn = el("button", { className: c.paused ? "resume" : "ghost danger", text: c.paused ? "Resume this key" : "Pause this key" });
    pauseBtn.addEventListener("click", function () {
      busy(pauseBtn, function () { return pauseScope({ kind: "credential", id: c.id }, !c.paused, result); });
    });
    var manageLink = c.manageUrl
      ? el("p", { className: "hint" }, [
          document.createTextNode("When you replace a key, revoke the old one at the provider too. "),
          el("a", { className: "linkout", href: c.manageUrl, target: "_blank", rel: "noopener noreferrer", text: "Open key settings" })
        ])
      : null;

    var openByDefault = hadFlash || c.source === "missing" || needsAttention(c);
    var manage = el("details", { className: "manage" }, [
      el("summary", { text: "Manage" }),
      el("div", { className: "manage-body" }, [
        el("div", { className: "block-label", text: "Expiry and notes" }),
        el("div", { className: "row" }, [expires, quick, note, saveMeta]),
        metaResult,
        el("div", { className: "block-label", text: "Key" }),
        el("div", { className: "row" }, [input, save]),
        manageLink,
        el("div", { className: "row" }, [testPath, test, c.source === "keychain" ? remove : null, pauseBtn]),
        result
      ])
    ]);
    if (openByDefault) manage.setAttribute("open", "");

    return el("div", { className: "card" + (c.expiryState === "expired" ? " expired" : c.expiryState === "soon" ? " attention" : "") }, [
      el("div", { className: "card-head" }, [
        el("div", {}, [el("div", { className: "name", text: c.id }), el("div", { className: "meta", text: (c.description ? c.description + " · " : "") + meta })]),
        el("div", { className: "pills" }, [
          c.paused ? el("span", { className: "pill paused", text: "Paused" }) : null,
          el("span", { className: "pill " + c.source, text: SOURCE_LABEL[c.source] }),
          el("span", { className: "pill " + pill.kind, text: pill.text })
        ])
      ]),
      usageLine(c),
      c.userNote ? el("div", { className: "usernote", text: c.userNote }) : null,
      envNote,
      manage
    ]);
  }

  function renderStoredOnly(k) {
    var result = el("div", { className: "result", role: "status" });
    if (flash && flash.id === k.id) { say(result, flash.kind, flash.text); flash = null; }
    var input = el("input", { type: "password", placeholder: "Paste a new key to replace it", spellcheck: "false", autocomplete: "off", "aria-label": "New key for " + k.id });
    var save = el("button", { text: "Replace" });
    var connect = el("button", { text: "Connect to an API" });
    var remove = el("button", { className: "ghost danger", text: "Remove key" });
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
      document.getElementById("addPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    remove.addEventListener("click", function () {
      if (!confirm("Remove the stored key " + k.id + " from Credential Manager?")) return;
      busy(remove, function () {
        return api("/api/secret/delete", { credentialId: k.id })
          .then(function () { return refresh(); })
          .catch(function (e) { say(result, "bad", e.message); });
      });
    });
    var pill = expiryPill(k);
    return el("div", { className: "card" }, [
      el("div", { className: "card-head" }, [
        el("div", {}, [el("div", { className: "name", text: k.id }), k.note ? el("div", { className: "meta", text: k.note }) : null]),
        el("div", { className: "pills" }, [
          el("span", { className: "pill keychain", text: "Stored only" }),
          k.expiryState !== "none" ? el("span", { className: "pill " + pill.kind, text: pill.text }) : null
        ])
      ]),
      el("div", { className: "manage-body" }, [el("div", { className: "row" }, [input, save, connect, remove]), result])
    ]);
  }

  function renderStats() {
    var all = state.credentials.concat(state.storedOnly);
    var attention = all.filter(needsAttention).length;
    var expired = all.filter(function (c) { return c.expiryState === "expired"; }).length;
    var withKey = state.credentials.filter(function (c) { return c.source !== "missing"; }).length;
    var missing = state.credentials.filter(function (c) { return c.source === "missing"; }).length;
    var holder = document.getElementById("stats");
    holder.replaceChildren();
    function tile(n, label, kind) {
      holder.appendChild(el("div", { className: "stat" + (kind ? " " + kind : "") }, [el("div", { className: "n", text: String(n) }), el("div", { className: "l", text: label })]));
    }
    tile(withKey + " / " + state.credentials.length, "APIs with a key");
    tile(attention, expired ? "Expired or expiring soon" : "Expiring within " + state.expiryWarningDays + " days", expired ? "bad" : attention ? "warn" : "");
    tile(missing, "APIs waiting for a key", missing ? "warn" : "");
    tile(state.storedOnly.length, "Stored but not connected");
  }

  function renderList() {
    var list = document.getElementById("list");
    list.replaceChildren();
    var rows = state.credentials.slice().sort(function (a, b) {
      return rank(a) - rank(b) || (a.expiryDays === null ? 99999 : a.expiryDays) - (b.expiryDays === null ? 99999 : b.expiryDays) || a.id.localeCompare(b.id);
    }).filter(function (c) {
      if (filter === "attention" && !needsAttention(c)) return false;
      if (filter === "nokey" && c.source !== "missing") return false;
      if (!search) return true;
      return (c.id + " " + c.description + " " + c.baseUrl + " " + c.userNote).toLowerCase().indexOf(search) !== -1;
    });
    if (!rows.length) {
      var anyRows = state.credentials.length > 0;
      list.appendChild(el("p", { className: "empty", text: anyRows ? "No keys match this view." : (state.policyExists ? "No APIs in the policy yet." : "No keys yet. Add your first one above.") }));
    }
    rows.forEach(function (c) { list.appendChild(renderCard(c)); });
  }

  function renderPause() {
    var p = state.pause;
    var panic = document.getElementById("panic");
    var allPaused = !!p.all || p.unreadable;
    panic.textContent = allPaused ? "Resume all access" : "Pause all access";
    panic.className = allPaused ? "resume" : "panic";
    var holder = document.getElementById("pauseBanner");
    holder.replaceChildren();
    if (!p.active) return;
    var lines = [];
    if (p.unreadable) {
      lines.push(el("strong", { text: "The pause file cannot be read, so every broker treats all access as paused." }));
      lines.push(el("div", { className: "hint", text: "Resuming writes a fresh, valid file." }));
    } else if (p.all) {
      lines.push(el("strong", { text: "All agent access is paused (since " + ago(p.all.at) + ")." }));
      lines.push(el("div", { className: "hint", text: "Every request is refused on its next call. Nothing was deleted." }));
    } else {
      lines.push(el("strong", { text: "Some access is paused." }));
    }
    var rows = el("div", { className: "row" });
    if (p.unreadable || p.all) {
      var resumeAll = el("button", { className: "resume", text: "Resume all access" });
      resumeAll.addEventListener("click", function () { busy(resumeAll, function () { return pauseAll(false); }); });
      rows.appendChild(resumeAll);
    }
    Object.keys(p.agents).forEach(function (id) {
      var b = el("button", { text: "Resume agent " + id });
      b.addEventListener("click", function () { busy(b, function () { return pauseScope({ kind: "agent", id: id }, false, null); }); });
      rows.appendChild(b);
    });
    Object.keys(p.credentials).forEach(function (id) {
      var b = el("button", { text: "Resume key " + id });
      b.addEventListener("click", function () { busy(b, function () { return pauseScope({ kind: "credential", id: id }, false, null); }); });
      rows.appendChild(b);
    });
    lines.push(rows);
    holder.appendChild(el("div", { className: "banner pause", role: "alert" }, lines));
  }

  function renderAgents() {
    var holder = document.getElementById("agentList");
    holder.replaceChildren();
    if (!state.agents.length) { holder.appendChild(el("p", { className: "empty", text: "No agents in the policy yet." })); return; }
    state.agents.forEach(function (a) {
      var paused = !!state.pause.agents[a.id];
      var btn = el("button", { className: paused ? "resume" : "ghost danger", text: paused ? "Resume" : "Pause" });
      btn.addEventListener("click", function () { busy(btn, function () { return pauseScope({ kind: "agent", id: a.id }, !paused, null); }); });
      var granted = state.credentials.filter(function (c) { return c.grantedTo.indexOf(a.id) !== -1; }).length;
      holder.appendChild(el("div", { className: "agent-row" }, [
        el("div", {}, [
          el("div", { className: "name", text: a.displayName && a.displayName !== a.id ? a.displayName + " (" + a.id + ")" : a.id }),
          el("div", { className: "meta", text: granted + (granted === 1 ? " key" : " keys") + (a.enabled ? "" : " · disabled in the policy") })
        ]),
        el("div", { className: "pills" }, [paused ? el("span", { className: "pill paused", text: "Paused" }) : null, btn])
      ]));
    });
  }

  function renderApprovals() {
    var create = document.getElementById("approvalCreate");
    var list = document.getElementById("approvalList");
    create.replaceChildren();
    list.replaceChildren();

    if (!state.approvable.length) {
      create.appendChild(el("p", { className: "empty", text: "No operation in the policy requires an approval, so there is nothing to approve." }));
    } else {
      var pick = el("select", { "aria-label": "Operation to approve" });
      state.approvable.forEach(function (o, i) {
        pick.appendChild(el("option", { value: String(i), text: o.agentId + " · " + o.credentialId + " · " + o.method + " " + o.path + " (" + o.operationId + ")" }));
      });
      var minutes = el("input", { type: "number", min: "1", max: "1440", value: "30", "aria-label": "Minutes until the approval expires" });
      var go = el("button", { className: "primary", text: "Create approval" });
      var out = el("div", { className: "result", role: "status" });
      go.addEventListener("click", function () {
        var o = state.approvable[Number(pick.value)];
        busy(go, function () {
          return api("/api/approvals/create", { agentId: o.agentId, credentialId: o.credentialId, operationId: o.operationId, minutes: Number(minutes.value) })
            .then(function (r) {
              return refresh().then(function () {
                var again = document.getElementById("approvalCreate");
                again.appendChild(el("div", { className: "banner warn" }, [
                  document.createTextNode("Give the agent this approval id: "),
                  el("span", { className: "appr-id", text: r.approvalId }),
                  el("div", { className: "hint", text: "Valid until " + r.expiresAt + ". It covers that one operation for that one agent." })
                ]));
              });
            })
            .catch(function (e) { say(out, "bad", e.message); });
        });
      });
      create.appendChild(el("div", { className: "row" }, [pick, el("label", { className: "hint" }, [document.createTextNode("Minutes "), minutes]), go]));
      create.appendChild(out);
    }

    var rows = state.approvals.slice().sort(function (a, b) { return Date.parse(b.expiresAt) - Date.parse(a.expiresAt); });
    if (!rows.length) { list.appendChild(el("p", { className: "empty", text: "No approvals yet." })); return; }
    rows.forEach(function (a) {
      var revoke = a.state === "active" ? el("button", { className: "ghost danger small", text: "Revoke" }) : null;
      if (revoke) revoke.addEventListener("click", function () {
        busy(revoke, function () { return api("/api/approvals/revoke", { approvalId: a.id }).then(function () { return refresh(); }); });
      });
      list.appendChild(el("div", { className: "appr-row" }, [
        el("div", {}, [
          el("div", { className: "appr-id", text: a.id }),
          el("div", { className: "meta", text: a.agentId + " · " + a.credentialId + " · " + a.operationId + " · until " + a.expiresAt })
        ]),
        el("div", { className: "pills" }, [el("span", { className: "pill " + (a.state === "active" ? "ok" : a.state === "revoked" ? "expired" : "none"), text: a.state }), revoke])
      ]));
    });
  }

  function render() {
    var where = document.getElementById("where");
    where.textContent = state.policyFile + (state.keychain ? " · keys in " + state.keychain : "");

    var banner = document.getElementById("banner");
    banner.replaceChildren();
    if (state.policyError) banner.appendChild(el("div", { className: "banner bad", text: "Policy file has a problem: " + state.policyError }));
    else if (!state.keychain) banner.appendChild(el("div", { className: "banner warn", text: "No keychain on this platform. Keys must be set as environment variables." }));
    var due = state.credentials.concat(state.storedOnly).filter(needsAttention).sort(function (a, b) { return a.expiryDays - b.expiryDays; });
    if (due.length) {
      var items = due.map(function (c) { var p = expiryPill(c); return el("li", { text: c.id + ": " + p.text.toLowerCase() }); });
      banner.appendChild(el("div", { className: "banner " + (due.some(function (c) { return c.expiryState === "expired"; }) ? "bad" : "warn") }, [
        document.createTextNode(due.length === 1 ? "1 key needs attention" : due.length + " keys need attention"),
        el("ul", {}, items)
      ]));
    }

    renderStats();
    renderList();
    renderPause();
    renderAgents();
    renderApprovals();

    var storedOnly = document.getElementById("storedOnly");
    storedOnly.replaceChildren();
    if (state.storedOnly.length) {
      storedOnly.appendChild(el("h3", { text: "Stored only (" + state.storedOnly.length + ")" }));
      storedOnly.appendChild(el("p", { className: "hint", text: "Housed in Credential Manager but not connected to an API, so no agent can use them. To connect one, use Connect to an API, then add the base URL above and leave the key field empty." }));
      state.storedOnly.forEach(function (k) { storedOnly.appendChild(renderStoredOnly(k)); });
    }

    var importAgent = document.getElementById("importAgent");
    var prevImport = importAgent.value;
    importAgent.replaceChildren();
    state.agents.forEach(function (a) { importAgent.appendChild(el("option", { value: a.id, text: a.id })); });
    importAgent.appendChild(el("option", { value: "__new", text: "New agent…" }));
    importAgent.appendChild(el("option", { value: "__none", text: "Nobody yet" }));
    importAgent.value = prevImport && importAgent.querySelector("option[value='" + prevImport + "']") ? prevImport : (state.agents.length ? state.agents[0].id : "__new");
    syncImportAgent();

    var choices = document.getElementById("grantChoices");
    var selected = new Set(Array.from(choices.querySelectorAll("input[data-agent]:checked"), function (x) { return x.value; }));
    var selectedGroups = new Set(Array.from(choices.querySelectorAll("input[data-group]:checked"), function (x) { return x.value; }));
    choices.replaceChildren();
    state.groups.forEach(function (g) {
      var box = el("input", { type: "checkbox", value: g.id, "data-group": g.id });
      box.checked = selectedGroups.has(g.id) && g.members.every(function (id) { return selected.has(id); });
      box.addEventListener("change", function () {
        choices.querySelectorAll("input[data-agent]").forEach(function (member) {
          if (g.members.includes(member.value)) member.checked = box.checked;
        });
        syncGroups();
      });
      choices.appendChild(el("label", {}, [box, document.createTextNode("Group: " + g.id)]));
    });
    state.agents.forEach(function (a) {
      var box = el("input", { type: "checkbox", value: a.id, "data-agent": a.id });
      box.checked = selected.has(a.id);
      box.addEventListener("change", syncGroups);
      choices.appendChild(el("label", {}, [box, document.createTextNode(a.displayName && a.displayName !== a.id ? a.displayName + " (" + a.id + ")" : a.id)]));
    });
    if (!state.agents.length) document.getElementById("newAgentToggle").checked = true;
    syncNewAgent();

    var connectAgent = document.getElementById("connectAgent");
    var prevConnect = connectAgent.value;
    connectAgent.replaceChildren();
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
        banner.replaceChildren();
        banner.appendChild(el("div", { className: "banner bad", text: e.message }));
      });
  }

  var form = document.getElementById("add");

  function applyPrefill() {
    if (!prefill || typeof prefill.id !== "string") return;
    var p = prefill;
    prefill = null;
    var holder = document.getElementById("requestBanner");
    holder.replaceChildren(el("div", { className: "banner warn", role: "alert" }, [
      el("strong", { text: String(p.requestedBy) + " asked for a key called " + p.id + "." }),
      el("div", { text: p.reason ? "Reason given: " + p.reason : "No reason given." }),
      el("div", { className: "hint", text: "An agent made this request. Check the details before you paste a key. Nothing is added until you press the button, and you choose who can use it." })
    ]));
    var existing = state.credentials.find(function (c) { return c.id === p.id; });
    if (existing) {
      var field = document.querySelector('input[aria-label="API key for ' + p.id + '"]');
      if (field) {
        var details = field.closest("details");
        if (details) details.setAttribute("open", "");
        field.scrollIntoView({ behavior: "smooth", block: "center" });
        field.focus();
      }
      return;
    }
    form.id.value = p.id;
    if (p.preset) {
      form.description.value = p.preset.label;
      form.baseUrl.value = p.preset.baseUrl;
      form.kind.value = p.preset.kind;
      syncKind();
      if (p.preset.paramName) form.paramName.value = p.preset.paramName;
    }
    document.getElementById("addPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    (p.preset ? form.value : form.baseUrl).focus();
  }

  function syncKind() {
    var kind = form.kind.value;
    document.getElementById("paramWrap").classList.toggle("hidden", kind !== "header" && kind !== "query");
    document.getElementById("paramLabel").textContent = kind === "query" ? "Parameter name" : "Header name";
    form.paramName.placeholder = kind === "query" ? "api_key" : "x-api-key";
    document.getElementById("queryRisk").classList.toggle("hidden", kind !== "query");
  }
  function syncGroups() {
    var chosen = new Set(Array.from(document.querySelectorAll("#grantChoices input[data-agent]:checked"), function (x) { return x.value; }));
    state.groups.forEach(function (g) {
      var box = Array.from(document.querySelectorAll("#grantChoices input[data-group]")).find(function (x) { return x.value === g.id; });
      if (box && !g.members.every(function (id) { return chosen.has(id); })) box.checked = false;
    });
  }
  function syncNewAgent() {
    document.getElementById("newAgentWrap").classList.toggle("hidden", !document.getElementById("newAgentToggle").checked);
  }
  form.kind.addEventListener("change", syncKind);
  document.getElementById("newAgentToggle").addEventListener("change", syncNewAgent);
  syncKind();

  // Quick expiry buttons on the add form.
  var addQuick = document.getElementById("expiryQuick");
  [["30 days", 30], ["90 days", 90], ["1 year", 365], ["Clear", null]].forEach(function (p) {
    var b = el("button", { type: "button", className: "small ghost", text: p[0] });
    b.addEventListener("click", function () { form.expires.value = p[1] === null ? "" : isoPlus(p[1]); });
    addQuick.appendChild(b);
  });

  // Search and filters.
  document.getElementById("search").addEventListener("input", function (e) {
    search = e.target.value.trim().toLowerCase();
    if (state) renderList();
  });
  Array.from(document.querySelectorAll(".chip")).forEach(function (chip) {
    chip.addEventListener("click", function () {
      filter = chip.getAttribute("data-filter");
      Array.from(document.querySelectorAll(".chip")).forEach(function (other) { other.setAttribute("aria-pressed", other === chip ? "true" : "false"); });
      if (state) renderList();
    });
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var result = document.getElementById("addResult");
    var queryParams = form.queryParams.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    var groupIds = Array.from(document.querySelectorAll("#grantChoices input[data-group]:checked"), function (box) { return box.value; });
    var covered = new Set(state.groups.filter(function (g) { return groupIds.includes(g.id); }).flatMap(function (g) { return g.members; }));
    var grants = Array.from(document.querySelectorAll("#grantChoices input[data-agent]:checked"), function (box) {
      return { agentId: box.value, queryParams: queryParams };
    }).filter(function (grant) { return !covered.has(grant.agentId); });
    if (document.getElementById("newAgentToggle").checked) {
      grants.push({ agentId: form.newAgent.value.trim(), queryParams: queryParams });
    }
    var body = {
      id: form.id.value.trim(),
      description: form.description.value.trim(),
      baseUrl: form.baseUrl.value.trim(),
      kind: form.kind.value,
      acknowledgeQueryRisk: form.acknowledgeQueryRisk.checked,
      value: form.value.value,
      grants: grants,
      groupIds: groupIds,
      groupQueryParams: queryParams
    };
    if (form.expires.value) body.expires = form.expires.value;
    if (form.userNote.value.trim()) body.userNote = form.userNote.value.trim();
    if (form.paramName.value.trim() && (body.kind === "header" || body.kind === "query")) body.paramName = form.paramName.value.trim();
    var button = form.querySelector("button[type=submit]");
    busy(button, function () {
      return api("/api/credential", body).then(function () {
        say(result, "ok", "Added " + body.id + (body.value ? " with its key." : ". Paste its key in the card below.") + " Restart Claude Code to pick it up.");
        form.reset(); syncKind(); syncNewAgent();
        return refresh();
      }).catch(function (err) { say(result, "bad", err.message); });
    });
  });

  // The header switch: type PAUSE to pause everything, RESUME to resume it.
  document.getElementById("panic").addEventListener("click", function (e) {
    var button = e.target;
    if (!state) return;
    var paused = !!state.pause.all || state.pause.unreadable;
    // The button is disabled while the dialog is open, so focus is put back
    // here once it is enabled again rather than by the dialog itself.
    busy(button, function () { return pauseAll(!paused); }).then(function () { button.focus(); });
  });

  document.getElementById("connectAgent").addEventListener("change", renderConnect);
  document.getElementById("copyCmd").addEventListener("click", function (e) {
    navigator.clipboard.writeText(document.getElementById("connectCmd").textContent).then(function () {
      e.target.textContent = "Copied"; setTimeout(function () { e.target.textContent = "Copy"; }, 1500);
    });
  });
  document.getElementById("close").addEventListener("click", function () {
    api("/api/close").finally(function () {
      document.body.replaceChildren();
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
    holder.replaceChildren();
    if (!scanRows.length) {
      holder.appendChild(el("p", { className: "empty", text: "No keys found in the usual places." }));
      return;
    }
    scanRows.forEach(function (r) {
      var check = el("input", { type: "checkbox", "aria-label": "Import " + r.name });
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
    refresh().then(applyPrefill);
  }
})();
</script>
</body>
</html>`;
}
