/**
 * The key manager page. Runs in the browser, served by keys-ui.ts on
 * loopback under a strict CSP. Every piece of data is placed with
 * textContent or DOM construction; nothing is ever assigned to innerHTML.
 *
 * The session token arrives in the URL fragment the key manager printed,
 * is moved into sessionStorage (same origin, this tab only) and wiped from
 * the address bar. From then on the fragment carries the hash route.
 */
import {
  accessChip,
  ago,
  EMPTY_FILTER,
  keysEmptyState,
  UNCONNECTED_PILL,
  UNCONNECTED_TITLE,
  unconnectedDetail,
  expiryText,
  filterActivity,
  groupHits,
  isoPlusDays,
  PAGES,
  parseLaunchFragment,
  parseRoute,
  rankSearch,
  routeHash,
  sortRows,
  toCsv,
  urgency,
} from "./logic.js";

import type { ActivityFilter, ActivityRecord, ExpiryState, Page, SearchHit, SearchItem, SearchKind } from "./logic.js";

// ---- server state types ------------------------------------------------------

interface Usage {
  lastAt: string | null;
  lastAgent: string | null;
  succeeded: number;
  denied: number;
  failed: number;
}

interface Credential {
  id: string;
  description: string;
  kind: "bearer" | "header" | "basic" | "query";
  paramName: string | null;
  baseUrl: string;
  envVar: string;
  source: "env" | "keychain" | "missing";
  note: string;
  grantedTo: string[];
  grantedGroups: string[];
  expires: string | null;
  userNote: string;
  rotatedAt: string | null;
  expiryState: ExpiryState;
  expiryDays: number | null;
  usage: Usage | null;
  manageUrl: string | null;
  paused: boolean;
}

interface StoredOnly {
  id: string;
  note: string;
  expires: string | null;
  userNote: string;
  rotatedAt: string | null;
  expiryState: ExpiryState;
  expiryDays: number | null;
}

interface Agent {
  id: string;
  displayName: string;
  enabled: boolean;
}

interface Approval {
  id: string;
  agentId: string;
  credentialId: string;
  operationId: string;
  expiresAt: string;
  state: "active" | "expired" | "revoked";
}

interface Approvable {
  agentId: string;
  credentialId: string;
  operationId: string;
  method: string;
  path: string;
}

interface Provider {
  id: string;
  label: string;
  baseUrl: string;
  kind: Credential["kind"];
  paramName: string | null;
  testPath: string | null;
  keysUrl: string | null;
}

interface PauseEntry {
  at: string;
  reason: string;
}

interface State {
  policyFile: string;
  policyExists: boolean;
  policyError: string | null;
  keychain: string | null;
  maxSecretBytes: number;
  credentials: Credential[];
  storedOnly: StoredOnly[];
  expiryWarningDays: number;
  usageWindowDays: number;
  pause: { active: boolean; unreadable: boolean; all: PauseEntry | null; agents: Record<string, PauseEntry>; credentials: Record<string, PauseEntry> };
  approvals: Approval[];
  approvable: Approvable[];
  agents: Agent[];
  groups: { id: string; members: string[] }[];
  register: { stdioEntry: string; policyFile: string; auditFile: string; approvalsFile: string; pauseFile: string; reloadMarker: string };
  paths: Record<string, string>;
  version: string;
  platform: string;
  providers: Provider[];
}

type PauseScope = { kind: "all" } | { kind: "agent"; id: string } | { kind: "credential"; id: string };

interface Prefill {
  id: string;
  reason?: string;
  requestedBy?: string;
  preset?: { label: string; baseUrl: string; kind: Credential["kind"]; paramName: string | null } | null;
}

// ---- tiny DOM helpers ----------------------------------------------------------

type Child = Node | string | null | undefined | false;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string | boolean | undefined> = {}, children: Child[] = []): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === "text") node.textContent = String(v);
    else if (k === "className") node.className = String(v);
    else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function text(s: string): Text {
  return document.createTextNode(s);
}

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing element #${id}`);
  return node as T;
}

function say(node: HTMLElement, kind: "" | "ok" | "bad" | "warn", message: string): void {
  node.className = `result ${kind}`;
  node.textContent = message;
}

function busy<T>(button: HTMLButtonElement, fn: () => Promise<T>): Promise<T> {
  button.disabled = true;
  return fn().finally(() => {
    button.disabled = false;
  });
}

function announce(message: string): void {
  const live = byId("live");
  live.textContent = "";
  window.setTimeout(() => {
    live.textContent = message;
  }, 30);
}

// ---- session, API --------------------------------------------------------------

const TOKEN_KEY = "cb-token";
let token = "";
let launchPrefill: Prefill | null = null;
{
  const fromHash = parseLaunchFragment(location.hash);
  if (fromHash.token) {
    token = fromHash.token;
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch {
      // Private mode without storage: the token lives in memory for this load.
    }
    const p = fromHash.prefill as Partial<Prefill> | null;
    if (p && typeof p.id === "string") launchPrefill = p as Prefill;
    history.replaceState(null, "", `${location.pathname}#/overview`);
  } else {
    try {
      token = sessionStorage.getItem(TOKEN_KEY) ?? "";
    } catch {
      token = "";
    }
  }
}

async function api<T = Record<string, unknown>>(path: string, body: unknown = {}): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as { error?: string } & T;
  if (!res.ok) throw new Error(data.error ?? `Request failed (${res.status})`);
  return data;
}

let state: State | null = null;

async function refresh(): Promise<void> {
  try {
    state = await api<State>("/api/state");
    render();
  } catch (error) {
    renderFatal(error instanceof Error ? error.message : "Could not load.");
  }
}

// ---- theme ---------------------------------------------------------------------

const THEME_KEY = "cb-theme";
type Theme = "light" | "dark" | "system";

function readTheme(): Theme {
  try {
    const t = localStorage.getItem(THEME_KEY);
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

function applyTheme(theme: Theme): void {
  const dark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  byId("theme").setAttribute("title", `Theme: ${theme}. Click to change.`);
}

function cycleTheme(): void {
  const order: Theme[] = ["system", "light", "dark"];
  const next = order[(order.indexOf(readTheme()) + 1) % order.length] ?? "system";
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    // Fine: it just will not be remembered.
  }
  applyTheme(next);
  toast(`Theme: ${next}.`);
}

// ---- modal, toast ----------------------------------------------------------------

interface ModalOptions {
  title: string;
  body: Child[];
  confirmLabel?: string;
  danger?: boolean;
  /** When set, the confirm button is disabled until this word is typed. */
  word?: string;
}

function openModal(opts: ModalOptions): Promise<boolean> {
  return new Promise((resolveModal) => {
    const host = byId("modalHost");
    const previous = document.activeElement as HTMLElement | null;
    const confirmBtn = el("button", { type: "button", className: `btn ${opts.danger ? "panic" : "primary"}`, text: opts.confirmLabel ?? "Confirm" });
    const cancelBtn = el("button", { type: "button", className: "btn", text: "Cancel" });
    const body = el("div", {}, opts.body);
    let field: HTMLInputElement | null = null;
    if (opts.word) {
      field = el("input", { type: "text", autocomplete: "off", spellcheck: "false", autocapitalize: "characters", placeholder: opts.word, "aria-describedby": "modalWhy" });
      body.append(el("label", { text: `Type ${opts.word} to confirm` }, [field]));
      confirmBtn.disabled = true;
    }
    const box = el("div", { className: `modal${opts.danger ? " danger" : ""}`, role: "dialog", "aria-modal": "true", "aria-labelledby": "modalTitle" }, [
      el("h2", { id: "modalTitle", text: opts.title }),
      body,
      el("div", { className: "actions" }, [cancelBtn, confirmBtn]),
    ]);
    const backdrop = el("div", { className: "backdrop" }, [box]);
    const matches = (): boolean => !opts.word || (field?.value.trim().toUpperCase() ?? "") === opts.word;
    const close = (result: boolean): void => {
      document.removeEventListener("keydown", onKey, true);
      backdrop.remove();
      previous?.focus?.();
      resolveModal(result);
    };
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.preventDefault();
        close(false);
        return;
      }
      if (e.key === "Enter" && !(e.target instanceof HTMLButtonElement)) {
        e.preventDefault();
        if (matches()) close(true);
        return;
      }
      if (e.key === "Tab") {
        const focusable = [...box.querySelectorAll<HTMLElement>("input, button")].filter((n) => !(n as HTMLButtonElement).disabled);
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (!first || !last) return;
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    field?.addEventListener("input", () => {
      confirmBtn.disabled = !matches();
    });
    confirmBtn.addEventListener("click", () => {
      if (matches()) close(true);
    });
    cancelBtn.addEventListener("click", () => close(false));
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) close(false);
    });
    document.addEventListener("keydown", onKey, true);
    host.replaceChildren(backdrop);
    (field ?? cancelBtn).focus();
  });
}

function toast(message: string, opts: { undo?: () => void; seconds?: number } = {}): void {
  const host = byId("toasts");
  const seconds = opts.seconds ?? (opts.undo ? 8 : 4);
  let left = seconds;
  let done = false;
  const count = el("span", { className: "count num", text: `${left}s` });
  const node = el("div", { className: "toast", role: "status" }, [el("span", { className: "grow", text: message })]);
  const finish = (): void => {
    if (done) return;
    done = true;
    window.clearInterval(timer);
    node.remove();
  };
  if (opts.undo) {
    const undoBtn = el("button", { type: "button", className: "btn", text: "Undo" });
    undoBtn.addEventListener("click", () => {
      if (done) return;
      finish();
      opts.undo?.();
    });
    node.append(count, undoBtn);
  }
  const timer = window.setInterval(() => {
    left -= 1;
    count.textContent = `${left}s`;
    if (left <= 0) finish();
  }, 1000);
  host.append(node);
  announce(message);
}

// ---- drawer ---------------------------------------------------------------------

let closeDrawer: (() => void) | null = null;

function openDrawer(title: string, body: Child[], footer: Child[] = [], opts: { onClose?: () => void } = {}): HTMLElement {
  closeDrawer?.();
  const host = byId("drawerHost");
  const previous = document.activeElement as HTMLElement | null;
  const closeBtn = el("button", { type: "button", className: "btn icon", "aria-label": "Close" }, [text("\u00d7")]);
  const panel = el("aside", { className: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "drawerTitle" }, [
    el("div", { className: "drawer-head" }, [el("h2", { id: "drawerTitle", text: title }), closeBtn]),
    el("div", { className: "drawer-body" }, body),
    footer.length ? el("div", { className: "drawer-foot" }, footer) : null,
  ]);
  const scrim = el("div", { className: "scrim" });
  const onKey = (e: KeyboardEvent): void => {
    if (byId("modalHost").childElementCount > 0) return;
    if (e.key === "Escape") {
      e.preventDefault();
      close();
      return;
    }
    if (e.key === "Tab") {
      const focusable = [...panel.querySelectorAll<HTMLElement>("input, select, textarea, button, a[href], summary, [tabindex]")].filter(
        (n) => !(n as HTMLButtonElement).disabled && n.offsetParent !== null,
      );
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };
  const close = (): void => {
    document.removeEventListener("keydown", onKey, true);
    scrim.remove();
    panel.remove();
    closeDrawer = null;
    opts.onClose?.();
    previous?.focus?.();
  };
  closeBtn.addEventListener("click", close);
  scrim.addEventListener("mousedown", close);
  document.addEventListener("keydown", onKey, true);
  host.replaceChildren(scrim, panel);
  closeDrawer = close;
  const firstField = panel.querySelector<HTMLElement>(".drawer-body input, .drawer-body select, .drawer-body button");
  (firstField ?? closeBtn).focus();
  return panel;
}

// ---- pause flows --------------------------------------------------------------

function setPause(scope: PauseScope, active: boolean, extra: { confirm?: string; undo?: boolean } = {}): Promise<void> {
  const body: Record<string, unknown> = { scope, active, reason: "" };
  if (extra.confirm) body["confirm"] = extra.confirm;
  if (extra.undo) body["undo"] = true;
  return api("/api/pause", body).then(() => refresh());
}

function scopeLabel(scope: PauseScope): string {
  return scope.kind === "all" ? "all access" : scope.kind === "agent" ? `agent ${scope.id}` : `key ${scope.id}`;
}

async function pauseScope(scope: PauseScope, active: boolean, result?: HTMLElement): Promise<void> {
  if (scope.kind === "all") return pauseAll(active);
  const label = scopeLabel(scope);
  const yes = await openModal(
    active
      ? {
          title: `Pause ${label}?`,
          danger: true,
          confirmLabel: "Pause",
          body: [el("p", { text: `${scope.kind === "agent" ? "Every request from this agent" : "Every request for this key"} will be refused on its next call. Nothing is deleted, and you can resume at any time.` })],
        }
      : {
          title: `Resume ${label}?`,
          confirmLabel: "Resume",
          body: [el("p", { text: `Requests ${scope.kind === "agent" ? "from this agent" : "for this key"} will be allowed again, as the policy already permits.` })],
        },
  );
  if (!yes) return;
  try {
    await setPause(scope, active);
    if (active) {
      toast(`Paused ${label}.`, {
        undo: () => {
          setPause(scope, false, { undo: true })
            .then(() => toast(`Resumed ${label}.`))
            .catch((e: Error) => (result ? say(result, "bad", e.message) : toast(e.message)));
        },
      });
    } else {
      toast(`Resumed ${label}.`);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (result) say(result, "bad", message);
    else toast(message);
  }
}

async function pauseAll(active: boolean): Promise<void> {
  if (!state) return;
  const agents = state.agents.length;
  const keys = state.credentials.length;
  const facts = el("div", { className: "facts" }, [
    el("span", { className: "pill", text: `${agents} ${agents === 1 ? "agent" : "agents"}` }),
    el("span", { className: "pill", text: `${keys} ${keys === 1 ? "key" : "keys"}` }),
  ]);
  const yes = await openModal(
    active
      ? {
          title: "Pause all access?",
          danger: true,
          confirmLabel: "Pause everything",
          word: "PAUSE",
          body: [el("p", { id: "modalWhy", text: "Every agent request will be refused on its next call. Nothing is deleted. You can resume at any time." }), facts],
        }
      : {
          title: "Resume all access?",
          confirmLabel: "Resume everything",
          word: "RESUME",
          body: [el("p", { id: "modalWhy", text: "Every agent that is not paused individually will be allowed to make requests again, as the policy permits." }), facts],
        },
  );
  if (!yes) return;
  try {
    await setPause({ kind: "all" }, active, { confirm: active ? "PAUSE" : "RESUME" });
    toast(active ? "All access is paused." : "All access is live again.");
  } catch (e) {
    toast(e instanceof Error ? e.message : String(e));
  }
}

// ---- search -----------------------------------------------------------------------

function searchItems(): SearchItem[] {
  if (!state) return [];
  const items: SearchItem[] = [];
  for (const c of state.credentials) {
    items.push({ kind: "key", title: c.id, subtitle: [c.description, c.baseUrl].filter(Boolean).join(" \u00b7 "), page: "keys", item: c.id, keywords: `${c.userNote} ${c.grantedTo.join(" ")}` });
  }
  for (const k of state.storedOnly) items.push({ kind: "key", title: k.id, subtitle: `${UNCONNECTED_TITLE}${k.note ? ` \u00b7 ${k.note}` : ""}`, page: "keys", item: k.id });
  for (const a of state.agents) items.push({ kind: "agent", title: a.id, subtitle: a.displayName !== a.id ? a.displayName : "Agent", page: "agents", item: a.id });
  for (const a of state.approvals) items.push({ kind: "approval", title: a.id, subtitle: `${a.agentId} \u00b7 ${a.credentialId} \u00b7 ${a.operationId} \u00b7 ${a.state}`, page: "approvals", item: a.id });
  for (const p of state.providers) items.push({ kind: "provider", title: p.label, subtitle: p.baseUrl, page: "keys", item: null, keywords: p.id });
  return items;
}

const KIND_TITLE: Record<SearchKind, string> = { key: "Keys", agent: "Agents", approval: "Approvals", provider: "Providers (new key)" };

function setupSearch(): void {
  const input = byId<HTMLInputElement>("search");
  const results = byId("searchResults");
  let hits: SearchHit[] = [];
  let selected = -1;

  const closeResults = (): void => {
    results.hidden = true;
    results.replaceChildren();
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
    selected = -1;
  };
  const choose = (hit: SearchHit): void => {
    closeResults();
    input.value = "";
    if (hit.item.kind === "provider") {
      const provider = state?.providers.find((p) => p.label === hit.item.title) ?? null;
      openNewKey({ provider });
      return;
    }
    go(hit.item.page, hit.item.item);
  };
  const paint = (): void => {
    results.replaceChildren();
    if (hits.length === 0) {
      results.append(el("div", { className: "empty", text: "Nothing matches." }));
    } else {
      let index = 0;
      for (const group of groupHits(hits)) {
        results.append(el("div", { className: "group", text: KIND_TITLE[group.kind] }));
        for (const hit of group.hits) {
          const i = index;
          const row = el("div", { className: "hit", role: "option", id: `hit-${i}`, "aria-selected": i === selected ? "true" : "false" }, [
            el("span", { className: "t", text: hit.item.title }),
            el("span", { className: "s", text: hit.item.subtitle }),
          ]);
          row.addEventListener("mousedown", (e) => {
            e.preventDefault();
            choose(hit);
          });
          results.append(row);
          index += 1;
        }
      }
    }
    results.hidden = false;
    input.setAttribute("aria-expanded", "true");
    if (selected >= 0) input.setAttribute("aria-activedescendant", `hit-${selected}`);
    else input.removeAttribute("aria-activedescendant");
  };
  input.addEventListener("input", () => {
    hits = rankSearch(searchItems(), input.value);
    selected = hits.length ? 0 : -1;
    if (input.value.trim()) paint();
    else closeResults();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (results.hidden) input.blur();
      closeResults();
      return;
    }
    if (results.hidden && input.value.trim() && (e.key === "ArrowDown" || e.key === "Enter")) {
      hits = rankSearch(searchItems(), input.value);
      selected = hits.length ? 0 : -1;
      paint();
      if (e.key === "ArrowDown") return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      selected = Math.min(hits.length - 1, selected + 1);
      paint();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selected = Math.max(0, selected - 1);
      paint();
    } else if (e.key === "Enter") {
      e.preventDefault();
      const hit = hits[selected];
      if (hit) choose(hit);
    }
  });
  input.addEventListener("blur", () => window.setTimeout(closeResults, 120));
  document.addEventListener("keydown", (e) => {
    const target = e.target as HTMLElement | null;
    const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT" || target.isContentEditable);
    if ((e.key === "/" && !typing) || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k")) {
      e.preventDefault();
      input.focus();
      input.select();
    }
  });
}

// ---- routing --------------------------------------------------------------------

let current: { page: Page; item: string | null } = { page: "overview", item: null };

function go(page: Page, item: string | null = null): void {
  location.hash = routeHash(page, item);
}

function onRoute(): void {
  current = parseRoute(location.hash);
  if (!location.hash) history.replaceState(null, "", `${location.pathname}#/overview`);
  closeDrawer?.();
  render();
  byId("page").focus({ preventScroll: true });
  window.scrollTo({ top: 0 });
}

// ---- rendering: header, banners ----------------------------------------------------

function renderFatal(message: string): void {
  byId("page").replaceChildren(el("div", { className: "card" }, [el("div", { className: "empty" }, [el("strong", { text: "The key manager could not load." }), el("span", { text: message })])]));
}

function renderHeader(): void {
  if (!state) return;
  const p = state.pause;
  const allPaused = !!p.all || p.unreadable;
  // An API counts as reachable when it has a key and at least one agent may use it.
  const reachable = state.credentials.filter((c) => c.source !== "missing" && c.grantedTo.length > 0).length;
  const chipState = accessChip(p, reachable);
  const chip = byId("statusChip");
  chip.className = `chip ${chipState.kind}`;
  chip.textContent = chipState.label;
  const pauseBtn = byId<HTMLButtonElement>("pauseBtn");
  pauseBtn.textContent = allPaused ? "Resume all access" : "Pause all access";
  pauseBtn.className = `btn ${allPaused ? "resume" : "panic"}`;
  for (const a of byId("tabs").querySelectorAll<HTMLAnchorElement>("a[data-page]")) {
    if (a.dataset["page"] === current.page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
}

/**
 * On narrow screens the page links fold into a menu button. The nav element
 * and its links are the same at every width; only their display changes, so
 * aria-current and the hash routes stay as they are.
 */
function setupMenu(): void {
  const button = byId<HTMLButtonElement>("menuBtn");
  const nav = byId("tabs");
  const setOpen = (open: boolean): void => {
    nav.classList.toggle("open", open);
    button.setAttribute("aria-expanded", open ? "true" : "false");
  };
  button.addEventListener("click", () => setOpen(!nav.classList.contains("open")));
  nav.addEventListener("click", (e) => {
    if ((e.target as HTMLElement).closest("a")) setOpen(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && nav.classList.contains("open")) {
      setOpen(false);
      button.focus();
    }
  });
  document.addEventListener("mousedown", (e) => {
    if (nav.classList.contains("open") && !byId("top").contains(e.target as Node)) setOpen(false);
  });
  window.addEventListener("hashchange", () => setOpen(false));
}

function renderBanners(): void {
  if (!state) return;
  const host = byId("banners");
  host.replaceChildren();
  const p = state.pause;
  if (p.active) {
    const rows = el("div", { className: "actions" });
    if (p.unreadable || p.all) {
      const b = el("button", { type: "button", className: "btn resume small", text: "Resume all access" });
      b.addEventListener("click", () => void busy(b, () => pauseAll(false)));
      rows.append(b);
    }
    for (const id of Object.keys(p.agents)) {
      const b = el("button", { type: "button", className: "btn small", text: `Resume agent ${id}` });
      b.addEventListener("click", () => void busy(b, () => pauseScope({ kind: "agent", id }, false)));
      rows.append(b);
    }
    for (const id of Object.keys(p.credentials)) {
      const b = el("button", { type: "button", className: "btn small", text: `Resume key ${id}` });
      b.addEventListener("click", () => void busy(b, () => pauseScope({ kind: "credential", id }, false)));
      rows.append(b);
    }
    const headline = p.unreadable
      ? "The pause file cannot be read, so every broker treats all access as paused."
      : p.all
        ? `All agent access is paused (since ${ago(p.all.at)}).`
        : "Some access is paused.";
    const detail = p.unreadable ? "Resuming writes a fresh, valid file." : "Every pause and resume is written to the audit log. Nothing was deleted.";
    host.append(el("div", { className: "banner bad", role: "alert" }, [el("div", { className: "grow" }, [el("strong", { text: headline }), el("div", { className: "hint", text: detail })]), rows]));
  }
  if (state.policyError) host.append(el("div", { className: "banner bad", text: `The policy file has a problem: ${state.policyError}` }));
  else if (!state.keychain) host.append(el("div", { className: "banner warn", text: "No keychain on this platform (or BROKER_KEYCHAIN=off). Keys must be set as environment variables." }));
}

function render(): void {
  if (!state) return;
  renderHeader();
  renderBanners();
  const page = byId("page");
  const focused = (document.activeElement as HTMLElement | null)?.dataset["fid"] ?? null;
  const views: Record<Page, () => Child[]> = {
    overview: renderOverview,
    keys: renderKeys,
    agents: renderAgents,
    approvals: renderApprovals,
    activity: renderActivity,
    import: renderImport,
    settings: renderSettings,
  };
  page.replaceChildren(...views[current.page]().filter((c): c is Node => c instanceof Node));
  if (focused) page.querySelector<HTMLElement>(`[data-fid="${CSS.escape(focused)}"]`)?.focus();
}

// ---- shared pieces ------------------------------------------------------------------

const KIND_LABEL: Record<Credential["kind"], string> = { bearer: "Bearer token", header: "Header", basic: "Basic auth", query: "URL parameter" };
const SOURCE_LABEL: Record<Credential["source"], string> = { keychain: "Key saved", env: "From environment", missing: "No key yet" };

function pageHead(title: string, lede: string, actions: Child[] = []): HTMLElement {
  return el("div", { className: "page-head" }, [el("div", {}, [el("h1", { text: title }), el("p", { className: "lede", text: lede })]), actions.length ? el("div", { className: "row" }, actions) : null]);
}

function needsAttention(c: { expiryState: ExpiryState }): boolean {
  return c.expiryState === "expired" || c.expiryState === "soon";
}

function statusPill(c: Credential): HTMLElement {
  if (c.paused) return el("span", { className: "pill paused", text: "Paused" });
  return el("span", { className: `pill ${c.source === "missing" ? "missing" : "ok"}`, text: SOURCE_LABEL[c.source] });
}

function expiryPill(c: { expiryState: ExpiryState; expiryDays: number | null; expires: string | null }): HTMLElement {
  const e = expiryText(c);
  return el("span", { className: `pill ${e.kind === "ok" ? "" : e.kind}`, text: e.text });
}

function explainStatus(status: number): ["ok" | "bad" | "warn", string] {
  if (status >= 200 && status < 300) return ["ok", `Works (${status}).`];
  if (status === 401 || status === 403) return ["bad", `Rejected (${status}). The key is wrong, expired, or lacks this permission.`];
  if (status === 404) return ["warn", "404 at that path. The key may be fine; try a real endpoint path."];
  if (status >= 300 && status < 400) return ["warn", `Redirect (${status}). Check the base URL.`];
  if (status === 0) return ["bad", "Could not reach the API."];
  return ["warn", `Got ${status}. Check the path or the API's docs.`];
}

function usageLine(c: Credential): HTMLElement {
  const parts: Child[] = [];
  if (c.usage?.lastAt) {
    parts.push(text("Last used "), el("strong", { text: ago(c.usage.lastAt) }), text(c.usage.lastAgent ? ` by ${c.usage.lastAgent}` : ""));
    parts.push(text(` \u00b7 last ${state?.usageWindowDays ?? 30} days: ${c.usage.succeeded} succeeded, ${c.usage.denied} denied, ${c.usage.failed} failed`));
  } else {
    parts.push(text("Not used by any agent yet"));
  }
  if (c.rotatedAt) parts.push(text(` \u00b7 key replaced ${ago(c.rotatedAt)}`));
  return el("div", { className: "usage" }, parts);
}

function quickExpiry(target: HTMLInputElement, withClear: boolean): HTMLElement {
  const quick = el("span", { className: "quick" });
  const options: [string, number | null][] = [["30 days", 30], ["90 days", 90], ["1 year", 365]];
  if (withClear) options.push(["Clear", null]);
  for (const [label, days] of options) {
    const b = el("button", { type: "button", className: "btn ghost small", text: label });
    b.addEventListener("click", () => {
      target.value = days === null ? "" : isoPlusDays(days);
    });
    quick.append(b);
  }
  return quick;
}

// ---- overview ---------------------------------------------------------------------

function renderOverview(): Child[] {
  if (!state) return [];
  const s = state;
  const all = [...s.credentials, ...s.storedOnly];
  const attention = all.filter(needsAttention);
  const expired = all.filter((c) => c.expiryState === "expired").length;
  const withKey = s.credentials.filter((c) => c.source !== "missing").length;
  const missing = s.credentials.filter((c) => c.source === "missing");
  const activeApprovals = s.approvals.filter((a) => a.state === "active").length;

  const tile = (n: string, label: string, page: Page, kind = ""): HTMLElement => {
    const a = el("a", { className: `tile ${kind}`, href: routeHash(page) }, [el("span", { className: "n", text: n }), el("span", { className: "l", text: label })]);
    return a;
  };
  const tiles = el("div", { className: "tiles" }, [
    tile(`${withKey} / ${s.credentials.length}`, "APIs with a key", "keys"),
    tile(String(s.storedOnly.length), s.storedOnly.length === 1 ? "Key not connected to an agent" : "Keys not connected to an agent", "keys", s.storedOnly.length ? "warn" : ""),
    tile(String(attention.length), expired ? "Expired or expiring soon" : `Expiring within ${s.expiryWarningDays} days`, "keys", expired ? "bad" : attention.length ? "warn" : ""),
    tile(String(s.agents.length), s.agents.length === 1 ? "Agent" : "Agents", "agents"),
    tile(String(activeApprovals), "Active approvals", "approvals", activeApprovals ? "ok" : ""),
  ]);

  const items: HTMLElement[] = [];
  if (s.pause.all || s.pause.unreadable) items.push(attentionRow("All access is paused", "Resume from the header when you are ready.", "settings", null, "bad", "Paused"));
  for (const id of Object.keys(s.pause.agents)) items.push(attentionRow(`Agent ${id} is paused`, "Resume it from the Agents page.", "agents", id, "bad", "Paused"));
  for (const id of Object.keys(s.pause.credentials)) items.push(attentionRow(`Key ${id} is paused`, "Resume it from its detail panel.", "keys", id, "bad", "Paused"));
  for (const c of attention.sort((a, b) => (a.expiryDays ?? 0) - (b.expiryDays ?? 0))) {
    items.push(attentionRow(c.id, expiryText(c).text, "keys", c.id, c.expiryState === "expired" ? "bad" : "warn", c.expiryState === "expired" ? "Expired" : "Expiring"));
  }
  for (const c of missing) items.push(attentionRow(c.id, "No key saved yet. Agents cannot use it until you paste one.", "keys", c.id, "warn", "No key"));
  for (const k of s.storedOnly) items.push(attentionRow(k.id, unconnectedDetail(s.keychain), "keys", null, "warn", UNCONNECTED_PILL));

  const attentionCard = el("div", { className: "card" }, [
    el("div", { className: "card-head" }, [el("h2", { text: "Needs attention" }), el("span", { className: `pill ${items.length ? "warn" : "ok"}`, text: items.length ? String(items.length) : "All clear" })]),
    el("div", { className: "card-body" }, items.length ? items : [el("div", { className: "empty" }, [el("strong", { text: "Nothing needs attention." }), el("span", { text: "Every key is saved, connected and in date, and nothing is paused." })])]),
  ]);

  const recent = el("div", { className: "card-body", id: "recentActivity" }, [el("p", { className: "hint", text: "Loading recent activity\u2026" })]);
  void api<{ records: ActivityRecord[] }>("/api/activity")
    .then(({ records }) => {
      recent.replaceChildren();
      const shown = records.filter((r) => r.outcome !== "requested" && r.outcome !== "executing").slice(0, 8);
      if (!shown.length) {
        recent.append(el("div", { className: "empty" }, [el("strong", { text: "No activity yet." }), el("span", { text: "Agent requests, pauses and reloads appear here." })]));
        return;
      }
      for (const r of shown) recent.append(activityRow(r));
    })
    .catch((e: Error) => recent.replaceChildren(el("p", { className: "result bad", text: e.message })));
  const activityCard = el("div", { className: "card" }, [
    el("div", { className: "card-head" }, [el("h2", { text: "Recent activity" }), el("a", { href: routeHash("activity"), text: "See all" })]),
    recent,
  ]);

  const quickValue = el("input", { type: "password", placeholder: "Paste an API key", "aria-label": "API key", autocomplete: "off", spellcheck: "false", required: true });
  const quickSave = el("button", { type: "submit", className: "btn primary", text: "Save key" });
  const quickResult = el("div", { className: "result", role: "status" });
  const quickForm = el("form", { className: "quick-add", autocomplete: "off" }, [
    el("div", { className: "quick-add-row" }, [quickValue, quickSave]),
    el("p", { className: "quick-add-hint", text: "Saved in your keychain. Connect it to an API and agent later." }),
    quickResult,
  ]);
  quickForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!quickValue.value.trim()) { say(quickResult, "bad", "Paste a key first."); return; }
    const id = `key-${crypto.randomUUID()}`;
    void busy(quickSave, () => api("/api/secret", { credentialId: id, value: quickValue.value })
      .then(async () => {
        quickValue.value = "";
        await refresh();
        toast("Key saved. Connect it to an API from the Keys page.");
      })
      .catch((error: Error) => say(quickResult, "bad", error.message)));
  });
  const detailedAdd = el("button", { type: "button", className: "btn quick-add-detailed", text: "Detailed setup" });
  detailedAdd.addEventListener("click", () => openNewKey({}));
  return [
    el("div", { className: "overview-intro" }, [
      el("div", {}, [
        el("h1", { text: "Access overview" }),
        el("p", { text: "Grant agents access to specific API operations and keep the keys with the broker." }),
        quickForm,
        detailedAdd,
      ]),
      el("img", { src: "/ui/broker-routing.svg", alt: "", width: "360", height: "160" }),
    ]),
    tiles,
    el("div", { className: "cols" }, [attentionCard, activityCard]),
  ];
}

function attentionRow(title: string, detail: string, page: Page, item: string | null, kind: "bad" | "warn", label: string): HTMLElement {
  return el("a", { className: "linkrow", href: routeHash(page, item) }, [
    el("div", {}, [el("div", { className: "name", text: title }), el("div", { className: "meta", text: detail })]),
    el("span", { className: `pill ${kind}`, text: label }),
  ]);
}

function activityRow(r: ActivityRecord): HTMLElement {
  const outcomeKind = r.outcome === "succeeded" ? "ok" : r.outcome === "denied" || r.outcome === "failed" ? "bad" : "";
  const what = r.method === "PAUSE" || r.method === "RESUME" ? `${r.method.toLowerCase()} ${r.pathname.slice(1).replace("/", " ")}` : `${r.method} ${r.host}${r.pathname}`;
  return el("div", { className: "list-row" }, [
    el("div", {}, [el("div", { className: "name", text: `${r.agentId}${r.credentialId !== "-" ? ` \u00b7 ${r.credentialId}` : ""}` }), el("div", { className: "meta", text: what })]),
    el("div", { className: "pills" }, [el("span", { className: `pill ${outcomeKind}`, text: r.outcome }), el("span", { className: "muted num", text: ago(r.at) })]),
  ]);
}

// ---- keys -----------------------------------------------------------------------------

type KeyFilter = "all" | "attention" | "nokey" | "paused";
type KeySort = "name" | "provider" | "status" | "expiry" | "lastUsed" | "agents";
let keyFilter: KeyFilter = "all";
let keySort: { key: KeySort; direction: "asc" | "desc" } = { key: "status", direction: "asc" };

function renderKeys(): Child[] {
  if (!state) return [];
  const s = state;
  const newKey = el("button", { type: "button", className: "btn primary", text: "New key" });
  newKey.addEventListener("click", () => openNewKey({}));

  const chips = el("div", { className: "chips", role: "group", "aria-label": "Filter keys" });
  const filters: [KeyFilter, string][] = [["all", "All"], ["attention", "Needs attention"], ["nokey", "No key yet"], ["paused", "Paused"]];
  for (const [f, label] of filters) {
    const b = el("button", { type: "button", text: label, "aria-pressed": keyFilter === f ? "true" : "false", "data-fid": `filter-${f}` });
    b.addEventListener("click", () => {
      keyFilter = f;
      render();
    });
    chips.append(b);
  }

  let rows = s.credentials.filter((c) => {
    if (keyFilter === "attention") return needsAttention(c);
    if (keyFilter === "nokey") return c.source === "missing";
    if (keyFilter === "paused") return c.paused;
    return true;
  });
  const sortKey: Record<KeySort, (c: Credential) => string | number | null> = {
    name: (c) => c.id,
    provider: (c) => c.baseUrl,
    status: (c) => urgency(c),
    expiry: (c) => c.expiryDays ?? null,
    lastUsed: (c) => (c.usage?.lastAt ? -Date.parse(c.usage.lastAt) : null),
    agents: (c) => c.grantedTo.length,
  };
  rows = sortRows(rows, sortKey[keySort.key], keySort.direction);

  const th = (label: string, key: KeySort, extra = ""): HTMLElement => {
    const active = keySort.key === key;
    const b = el("button", { type: "button", text: label, "aria-sort": active ? (keySort.direction === "asc" ? "ascending" : "descending") : undefined, "data-fid": `sort-${key}` });
    b.addEventListener("click", () => {
      keySort = { key, direction: active && keySort.direction === "asc" ? "desc" : "asc" };
      render();
    });
    return el("th", { className: extra, scope: "col" }, [b]);
  };
  const tbody = el("tbody");
  for (const c of rows) {
    const tr = el("tr", { tabindex: "0", "aria-selected": current.item === c.id ? "true" : "false", "data-fid": `key-${c.id}` }, [
      el("td", { className: "name" }, [text(c.id), el("span", { className: "sub", text: c.description || KIND_LABEL[c.kind] })]),
      el("td", {}, [el("span", { className: "sub", text: new URL(c.baseUrl).host })]),
      el("td", {}, [statusPill(c)]),
      el("td", {}, [expiryPill(c)]),
      el("td", { className: "num muted", text: c.usage?.lastAt ? ago(c.usage.lastAt) : "never" }),
      el("td", { className: "num", text: c.grantedTo.length ? c.grantedTo.join(", ") : "nobody" }),
    ]);
    const open = (): void => go("keys", c.id);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        open();
      }
    });
    tbody.append(tr);
  }
  const table = el("table", { className: "data" }, [
    el("thead", {}, [el("tr", {}, [th("Name", "name"), th("Provider", "provider"), th("Status", "status"), th("Expiry", "expiry"), th("Last used", "lastUsed", "num"), th("Agents", "agents")])]),
    tbody,
  ]);
  // "No keys yet" is only true when there is nothing anywhere: no API in the
  // policy and nothing saved in the keychain either.
  const emptyKind = keysEmptyState({ policyExists: s.policyExists, credentials: s.credentials.length, unconnected: s.storedOnly.length, visible: rows.length });
  const emptyNode = (): HTMLElement => {
    if (emptyKind === "filtered") {
      const b = el("button", { type: "button", className: "btn", text: "Show all keys" });
      b.addEventListener("click", () => {
        keyFilter = "all";
        render();
      });
      return el("div", { className: "empty" }, [el("strong", { text: "No keys match this view." }), b]);
    }
    if (emptyKind === "unconnected") {
      const n = s.storedOnly.length;
      return el("div", { className: "empty" }, [
        el("strong", { text: `No API uses your ${n === 1 ? "saved key" : `${n} saved keys`} yet.` }),
        el("span", { text: `${n === 1 ? "It is" : "They are"} saved in ${s.keychain ?? "the keychain"}, but no API in the policy uses ${n === 1 ? "it" : "them"}, so no agent can. Connect one to an API below.` }),
      ]);
    }
    const b = el("button", { type: "button", className: "btn primary", text: "Add your first key" });
    b.addEventListener("click", () => openNewKey({}));
    return el("div", { className: "empty" }, [el("strong", { text: emptyKind === "no-apis" ? "No APIs in the policy yet." : "No keys yet." }), el("span", { text: "Add a key and choose which agent may use it. The agent gets read access only." }), b]);
  };
  const keysCard = el("div", { className: "card" }, [rows.length ? el("div", { className: "table-wrap" }, [table]) : emptyNode()]);

  const stored: Child[] = [];
  if (s.storedOnly.length) {
    const list = el("div", { className: "list" });
    for (const k of s.storedOnly) {
      const tr = el("div", { className: "list-row", "data-fid": `stored-${k.id}` }, [
        el("div", {}, [el("div", { className: "name", text: k.id }), el("div", { className: "meta", text: k.note ? `${k.note} · ${unconnectedDetail(s.keychain)}` : unconnectedDetail(s.keychain) })]),
        el("div", { className: "pills" }, [el("span", { className: "pill warn", text: UNCONNECTED_PILL }), k.expiryState !== "none" ? expiryPill(k) : null, storedActions(k)]),
      ]);
      list.append(tr);
    }
    stored.push(
      el("div", { className: "card", id: "unconnected" }, [
        el("div", { className: "card-head" }, [el("h2", { text: `${UNCONNECTED_TITLE} (${s.storedOnly.length})` }), el("span", { className: "hint", text: unconnectedDetail(s.keychain) })]),
        el("div", { className: "card-body" }, [list]),
      ]),
    );
  }

  if (current.item) {
    const c = s.credentials.find((x) => x.id === current.item);
    if (c) window.setTimeout(() => openKeyDetail(c), 0);
  }
  return [
    pageHead("Keys", "Every API the policy knows, with its key status, expiry and who may use it. Click a row to manage it.", [newKey]),
    el("div", { className: "toolbar" }, [chips, el("div", { className: "right" }, [el("span", { className: "hint num", text: `${rows.length} of ${s.credentials.length}` })])]),
    keysCard,
    ...stored,
  ];
}

function storedActions(k: StoredOnly): HTMLElement {
  const connect = el("button", { type: "button", className: "btn small", text: "Connect to an API" });
  connect.addEventListener("click", () => openNewKey({ id: k.id, storedOnly: true }));
  const replace = el("button", { type: "button", className: "btn small ghost", text: "Replace" });
  replace.addEventListener("click", () => openStoredReplace(k));
  const remove = el("button", { type: "button", className: "btn small ghost danger", text: "Remove" });
  const removeStored = async (): Promise<void> => {
    const yes = await openModal({ title: `Remove the stored key ${k.id}?`, danger: true, confirmLabel: "Remove", body: [el("p", { text: "It is deleted from the keychain. This cannot be undone." })] });
    if (!yes) return;
    try {
      await api("/api/secret/delete", { credentialId: k.id });
      toast(`Removed ${k.id}.`);
      await refresh();
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e));
    }
  };
  remove.addEventListener("click", () => void removeStored());
  return el("span", { className: "pills" }, [connect, replace, remove]);
}

function openStoredReplace(k: StoredOnly): void {
  const input = el("input", { type: "password", placeholder: "Paste the new key", spellcheck: "false", autocomplete: "off", "aria-label": `New key for ${k.id}` });
  const result = el("div", { className: "result", role: "status" });
  const save = el("button", { type: "button", className: "btn primary", text: "Replace key" });
  save.addEventListener("click", () => {
    void busy(save, () =>
      api("/api/secret", { credentialId: k.id, value: input.value })
        .then(() => {
          input.value = "";
          closeDrawer?.();
          toast(`Replaced the key for ${k.id}.`);
          return refresh();
        })
        .catch((e: Error) => say(result, "bad", e.message)),
    );
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") save.click();
  });
  openDrawer(`Replace key: ${k.id}`, [el("div", { className: "section" }, [el("p", { className: "hint", text: "The new value replaces the stored one. This page never shows a key back." }), input, result])], [save]);
}

function openKeyDetail(c: Credential): void {
  const result = el("div", { className: "result", role: "status" });
  const metaResult = el("div", { className: "result", role: "status" });

  const expires = el("input", { type: "date", "aria-label": `Expiry date for ${c.id}` });
  expires.value = c.expires ?? "";
  const note = el("textarea", { maxlength: "500", placeholder: "Where it was created, what it is for, how to rotate it", "aria-label": `Notes for ${c.id}` });
  note.value = c.userNote;
  const saveMeta = el("button", { type: "button", className: "btn", text: "Save details" });
  saveMeta.addEventListener("click", () => {
    void busy(saveMeta, () =>
      api("/api/meta", { credentialId: c.id, expires: expires.value || null, note: note.value })
        .then(() => {
          say(metaResult, "ok", "Details saved.");
          return refresh();
        })
        .catch((e: Error) => say(metaResult, "bad", e.message)),
    );
  });

  const keyInput = el("input", { type: "password", placeholder: c.source === "missing" ? "Paste the key" : "Paste a new key to replace it", spellcheck: "false", autocomplete: "off", "aria-label": `API key for ${c.id}` });
  const save = el("button", { type: "button", className: "btn primary", text: c.source === "missing" ? "Save key" : "Replace key" });
  save.addEventListener("click", () => {
    void busy(save, () =>
      api("/api/secret", { credentialId: c.id, value: keyInput.value })
        .then(() => {
          keyInput.value = "";
          say(result, "ok", "Saved. Restart the MCP client (or use hot reload) to pick it up. If this is a new key, update the expiry date.");
          toast(`Saved the key for ${c.id}.`);
          return refresh();
        })
        .catch((e: Error) => say(result, "bad", e.message)),
    );
  });
  keyInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") save.click();
  });
  const testPath = el("input", { type: "text", placeholder: "Test path, e.g. /models (optional)", spellcheck: "false", "aria-label": `Test path for ${c.id}` });
  const test = el("button", { type: "button", className: "btn", text: "Test" });
  test.addEventListener("click", () => {
    void busy(test, () =>
      api<{ status: number }>("/api/test", { credentialId: c.id, path: testPath.value })
        .then((r) => {
          const [kind, message] = explainStatus(r.status);
          say(result, kind, message);
        })
        .catch((e: Error) => say(result, "bad", e.message)),
    );
  });
  const pauseBtn = el("button", { type: "button", className: `btn ${c.paused ? "resume" : "danger"}`, text: c.paused ? "Resume this key" : "Pause this key" });
  pauseBtn.addEventListener("click", () => void busy(pauseBtn, () => pauseScope({ kind: "credential", id: c.id }, !c.paused, result)));
  const remove = el("button", { type: "button", className: "btn ghost danger", text: "Remove key" });
  const removeKey = async (): Promise<void> => {
    const yes = await openModal({ title: `Remove the saved key for ${c.id}?`, danger: true, confirmLabel: "Remove", body: [el("p", { text: "The API stays in the policy; only the key is deleted from the keychain." })] });
    if (!yes) return;
    try {
      await api("/api/secret/delete", { credentialId: c.id });
      toast(`Removed the key for ${c.id}.`);
      await refresh();
    } catch (e) {
      say(result, "bad", e instanceof Error ? e.message : String(e));
    }
  };
  remove.addEventListener("click", () => void removeKey());

  const facts = el("dl", { className: "kv" }, [
    el("dt", { text: "Base URL" }), el("dd", { text: c.baseUrl }),
    el("dt", { text: "Key style" }), el("dd", { text: `${KIND_LABEL[c.kind]}${c.paramName ? ` (${c.paramName})` : ""}` }),
    el("dt", { text: "Environment" }), el("dd", { text: c.envVar }),
    el("dt", { text: "Agents" }), el("dd", { text: c.grantedTo.length ? c.grantedTo.join(", ") : "nobody" }),
    c.grantedGroups.length ? el("dt", { text: "Groups" }) : null, c.grantedGroups.length ? el("dd", { text: c.grantedGroups.join(", ") }) : null,
  ]);
  const body: Child[] = [
    el("div", { className: "pills" }, [statusPill(c), expiryPill(c), c.source === "env" ? el("span", { className: "pill info", text: `Set by ${c.envVar}` }) : null]),
    c.description ? el("p", { className: "hint", text: c.description }) : null,
    usageLine(c),
    c.note ? el("p", { className: "hint", text: c.note }) : null,
    el("div", { className: "section" }, [el("h3", { text: "Key" }), el("div", { className: "row" }, [keyInput, save]), el("div", { className: "row" }, [testPath, test]), result,
      c.manageUrl ? el("p", { className: "hint" }, [text("When you replace a key, revoke the old one at the provider too. "), el("a", { href: c.manageUrl, target: "_blank", rel: "noopener noreferrer", text: "Open key settings" })]) : null]),
    el("div", { className: "section" }, [el("h3", { text: "Expiry and notes" }), el("div", { className: "row" }, [expires, quickExpiry(expires, true)]), note, el("div", { className: "row" }, [saveMeta]), metaResult]),
    el("div", { className: "section" }, [el("h3", { text: "Details" }), facts]),
  ];
  openDrawer(c.id, body, [c.source === "keychain" ? remove : null, pauseBtn], { onClose: () => { if (current.item === c.id) history.replaceState(null, "", routeHash("keys")); current = { page: "keys", item: null }; render(); } });
}

// ---- new key drawer -----------------------------------------------------------------

interface NewKeyOptions {
  provider?: Provider | null;
  id?: string;
  storedOnly?: boolean;
  prefill?: Prefill;
}

function openNewKey(opts: NewKeyOptions): void {
  if (!state) return;
  const s = state;
  const form = el("form", { className: "stack", autocomplete: "off" });
  const result = el("div", { className: "result", role: "status" });

  const idInput = el("input", { name: "id", placeholder: "openai", required: true, pattern: "[a-z0-9][a-z0-9._-]{1,63}", spellcheck: "false", "aria-describedby": "idHint" });
  const description = el("input", { name: "description", placeholder: "OpenAI API, personal project key" });
  const baseUrl = el("input", { name: "baseUrl", placeholder: "https://api.openai.com/v1", required: true, spellcheck: "false" });
  const kind = el("select", { name: "kind", "aria-label": "How the key is sent" }, [
    el("option", { value: "bearer", text: "Authorization: Bearer <key> (most APIs)" }),
    el("option", { value: "header", text: "Custom header (e.g. x-api-key)" }),
    el("option", { value: "basic", text: "Basic auth (user:password)" }),
    el("option", { value: "query", text: "In the URL (?api_key=\u2026)" }),
  ]);
  const paramName = el("input", { name: "paramName", placeholder: "x-api-key" });
  const paramLabel = el("span", { text: "Header name" });
  const paramWrap = el("label", { className: "field" }, [paramLabel, paramName]);
  const queryRisk = el("input", { type: "checkbox", name: "acknowledgeQueryRisk" });
  const queryWrap = el("label", { className: "check" }, [queryRisk, el("span", { text: "I understand keys in URLs often end up in server and proxy logs. Prefer a header if the API supports one." })]);
  const value = el("input", { name: "value", type: "password", placeholder: opts.storedOnly ? "Already stored; leave empty" : "Paste the key", spellcheck: "false" });
  const expires = el("input", { name: "expires", type: "date" });
  const userNote = el("textarea", { name: "userNote", maxlength: "500", placeholder: "Where it was created, what it is for, how to rotate it" });
  const queryParams = el("input", { name: "queryParams", placeholder: "q, limit, page" });
  const newAgentToggle = el("input", { type: "checkbox" });
  const newAgent = el("input", { name: "newAgent", placeholder: "claude", pattern: "[a-z0-9][a-z0-9._-]{1,63}" });
  const newAgentWrap = el("label", { className: "field", hidden: true }, [text("New agent name"), newAgent]);

  const syncKind = (): void => {
    const k = kind.value;
    paramWrap.hidden = k !== "header" && k !== "query";
    paramLabel.textContent = k === "query" ? "Parameter name" : "Header name";
    paramName.placeholder = k === "query" ? "api_key" : "x-api-key";
    queryWrap.hidden = k !== "query";
  };
  kind.addEventListener("change", syncKind);
  newAgentToggle.addEventListener("change", () => {
    newAgentWrap.hidden = !newAgentToggle.checked;
  });

  // Provider picker: a fixed table from the broker. Picking one fills the address and key style.
  let chosen: Provider | null = null;
  const providerSearch = el("input", { type: "search", placeholder: "Find a provider", "aria-label": "Find a provider", spellcheck: "false" });
  const grid = el("div", { className: "providers", role: "listbox", "aria-label": "Known providers" });
  const paintProviders = (): void => {
    grid.replaceChildren();
    const q = providerSearch.value.trim().toLowerCase();
    const starts = (p: Provider): number => (p.label.toLowerCase().startsWith(q) || p.id.startsWith(q) ? 0 : 1);
    const list = s.providers
      .filter((p) => !q || p.label.toLowerCase().includes(q) || p.id.includes(q) || p.baseUrl.includes(q))
      .sort((a, b) => (q ? starts(a) - starts(b) : 0) || a.label.localeCompare(b.label));
    for (const p of list) {
      const b = el("button", { type: "button", className: "provider", role: "option", "aria-pressed": chosen?.id === p.id ? "true" : "false" }, [el("span", { className: "l", text: p.label }), el("span", { className: "h", text: new URL(p.baseUrl).host })]);
      b.addEventListener("click", () => pickProvider(chosen?.id === p.id ? null : p));
      grid.append(b);
    }
    const other = el("button", { type: "button", className: "provider", role: "option", "aria-pressed": chosen === null ? "true" : "false" }, [el("span", { className: "l", text: "Other" }), el("span", { className: "h", text: "Enter the address yourself" })]);
    other.addEventListener("click", () => pickProvider(null));
    grid.append(other);
  };
  const pickProvider = (p: Provider | null): void => {
    chosen = p;
    if (p) {
      if (!idInput.value) idInput.value = p.id;
      description.value = p.label;
      baseUrl.value = p.baseUrl;
      kind.value = p.kind;
      paramName.value = p.paramName ?? "";
      syncKind();
    }
    paintProviders();
    (p ? value : baseUrl).focus();
  };
  providerSearch.addEventListener("input", paintProviders);

  const grants = el("div", { className: "choices" });
  for (const g of s.groups) {
    const box = el("input", { type: "checkbox", value: g.id, "data-group": g.id });
    box.addEventListener("change", () => {
      for (const member of grants.querySelectorAll<HTMLInputElement>("input[data-agent]")) if (g.members.includes(member.value)) member.checked = box.checked;
    });
    grants.append(el("label", { className: "check" }, [box, text(`Group: ${g.id}`)]));
  }
  for (const a of s.agents) {
    const box = el("input", { type: "checkbox", value: a.id, "data-agent": a.id });
    grants.append(el("label", { className: "check" }, [box, text(a.displayName && a.displayName !== a.id ? `${a.displayName} (${a.id})` : a.id)]));
  }
  if (!s.agents.length) {
    newAgentToggle.checked = true;
    newAgentWrap.hidden = false;
  }

  form.append(
    el("div", { className: "section" }, [el("h3", { text: "Provider" }), providerSearch, grid]),
    el("div", { className: "form-grid" }, [
      el("label", { className: "field" }, [text("Short name"), idInput, el("span", { className: "hint", id: "idHint", text: "Lowercase letters, digits, dots and dashes. The agent picks the key by this name." })]),
      el("label", { className: "field" }, [text("What it is"), description]),
      el("label", { className: "field full" }, [text("Base URL"), baseUrl, el("span", { className: "hint", text: "The agent can only reach paths under this address." })]),
      el("label", { className: "field" }, [text("How the key is sent"), kind]),
      paramWrap,
      el("div", { className: "full" }, [queryWrap]),
      el("label", { className: "field full" }, [text("API key"), value, el("span", { className: "hint", text: `Stored in ${s.keychain ?? "the keychain"} under credential-broker/<short name>. Never shown back.` })]),
      el("div", { className: "field" }, [text("Expires"), expires, quickExpiry(expires, true)]),
      el("label", { className: "field" }, [text("Notes"), userNote]),
      el("div", { className: "field full" }, [text("Who can use it"), grants, el("span", { className: "hint", text: "Read access only (GET). Write access stays a hand-written policy decision." })]),
      el("details", { className: "more full" }, [
        el("summary", { text: "More options" }),
        el("div", { className: "form-grid" }, [
          el("label", { className: "check full" }, [newAgentToggle, text("Add a new agent")]),
          newAgentWrap,
          el("label", { className: "field full" }, [text("Query parameters the agent may use (optional)"), queryParams, el("span", { className: "hint", text: "Any query parameter not listed is refused." })]),
        ]),
      ]),
    ]),
    result,
  );
  syncKind();
  paintProviders();

  const submit = el("button", { type: "submit", className: "btn primary", text: "Add key" });
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const qp = queryParams.value.split(",").map((x) => x.trim()).filter(Boolean);
    const groupIds = [...grants.querySelectorAll<HTMLInputElement>("input[data-group]:checked")].map((b) => b.value);
    const covered = new Set(s.groups.filter((g) => groupIds.includes(g.id)).flatMap((g) => g.members));
    const chosenGrants = [...grants.querySelectorAll<HTMLInputElement>("input[data-agent]:checked")].map((b) => ({ agentId: b.value, queryParams: qp })).filter((g) => !covered.has(g.agentId));
    if (newAgentToggle.checked && newAgent.value.trim()) chosenGrants.push({ agentId: newAgent.value.trim(), queryParams: qp });
    const body: Record<string, unknown> = {
      id: idInput.value.trim(),
      description: description.value.trim(),
      baseUrl: baseUrl.value.trim(),
      kind: kind.value,
      acknowledgeQueryRisk: queryRisk.checked,
      value: value.value,
      grants: chosenGrants,
      groupIds,
      groupQueryParams: qp,
    };
    if (expires.value) body["expires"] = expires.value;
    if (userNote.value.trim()) body["userNote"] = userNote.value.trim();
    if (paramName.value.trim() && (kind.value === "header" || kind.value === "query")) body["paramName"] = paramName.value.trim();
    void busy(submit, () =>
      api("/api/credential", body)
        .then(() => {
          closeDrawer?.();
          toast(`Added ${String(body["id"])}${value.value ? " with its key." : ". Paste its key from the Keys page."}`);
          return refresh().then(() => go("keys", String(body["id"])));
        })
        .catch((err: Error) => say(result, "bad", err.message)),
    );
  });
  submit.addEventListener("click", () => form.requestSubmit());

  const head: Child[] = [];
  if (opts.prefill) {
    head.push(
      el("div", { className: "banner warn", role: "alert" }, [
        el("div", { className: "grow" }, [
          el("strong", { text: `${opts.prefill.requestedBy ?? "An agent"} asked for a key called ${opts.prefill.id}.` }),
          el("div", { text: opts.prefill.reason ? `Reason given: ${opts.prefill.reason}` : "No reason given." }),
          el("div", { className: "hint", text: "An agent made this request. Check the details before you paste a key. Nothing is added until you press the button, and you choose who can use it." }),
        ]),
      ]),
    );
  }
  openDrawer(opts.storedOnly ? `Connect ${opts.id ?? ""} to an API` : "New key", [...head, form], [submit]);

  if (opts.id) idInput.value = opts.id;
  if (opts.prefill) {
    idInput.value = opts.prefill.id;
    const preset = opts.prefill.preset ? s.providers.find((p) => p.baseUrl === opts.prefill?.preset?.baseUrl) ?? null : null;
    if (preset) pickProvider(preset);
    else if (opts.prefill.preset) {
      description.value = opts.prefill.preset.label;
      baseUrl.value = opts.prefill.preset.baseUrl;
      kind.value = opts.prefill.preset.kind;
      paramName.value = opts.prefill.preset.paramName ?? "";
      syncKind();
      value.focus();
    } else {
      baseUrl.focus();
    }
  } else if (opts.provider) {
    pickProvider(opts.provider);
  } else if (opts.id) {
    baseUrl.focus();
  } else {
    providerSearch.focus();
  }
}

// ---- agents --------------------------------------------------------------------------

function renderAgents(): Child[] {
  if (!state) return [];
  const s = state;
  const list = el("div", { className: "list" });
  const addAgent = el("button", { type: "button", className: "btn primary", text: "Add agent", "data-fid": "addAgent" });
  addAgent.addEventListener("click", () => openNewAgent());
  if (!s.agents.length) {
    list.append(el("div", { className: "empty" }, [el("strong", { text: "No agents in the policy yet." }), el("span", { text: "Add one here, or add a key and tick Add a new agent." })]));
  }
  for (const a of s.agents) {
    const paused = !!s.pause.agents[a.id];
    const keys = s.credentials.filter((c) => c.grantedTo.includes(a.id));
    const btn = el("button", { type: "button", className: `btn small ${paused ? "resume" : "danger"}`, text: paused ? "Resume" : "Pause", "data-fid": `agent-${a.id}` });
    btn.addEventListener("click", () => void busy(btn, () => pauseScope({ kind: "agent", id: a.id }, !paused)));
    const reach = el("div", { className: "pills" }, keys.map((c) => el("a", { className: "pill accent", href: routeHash("keys", c.id), text: c.id })));
    list.append(
      el("div", { className: "list-row", "aria-current": current.item === a.id ? "true" : undefined }, [
        el("div", {}, [
          el("div", { className: "name", text: a.displayName && a.displayName !== a.id ? `${a.displayName} (${a.id})` : a.id }),
          el("div", { className: "meta", text: `${keys.length} ${keys.length === 1 ? "key" : "keys"}${a.enabled ? "" : " \u00b7 disabled in the policy"}` }),
          keys.length ? reach : null,
        ]),
        el("div", { className: "pills" }, [paused ? el("span", { className: "pill paused", text: "Paused" }) : el("span", { className: "pill ok", text: "Live" }), btn]),
      ]),
    );
  }
  return [
    pageHead("Agents", "Each agent is one broker process with its own identity. Pausing one does not touch the others; it takes effect on the next request and nothing is deleted.", [addAgent]),
    el("div", { className: "card" }, [el("div", { className: "card-body" }, [list])]),
  ];
}

/**
 * Add agent drawer. Same pattern as New key: a form in the side drawer that
 * writes through the policy-save path. The agent starts with no grants; only
 * the APIs ticked here become read grants (GET under the base URL). It never
 * sees or carries a key.
 */
function openNewAgent(): void {
  if (!state) return;
  const s = state;
  const form = el("form", { className: "stack", autocomplete: "off" });
  const result = el("div", { className: "result", role: "status" });
  const idInput = el("input", { name: "id", placeholder: "claude", required: true, pattern: "[a-z0-9][a-z0-9._-]{1,63}", spellcheck: "false", "aria-describedby": "agentIdHint" });
  const displayName = el("input", { name: "displayName", placeholder: "Claude Code", maxlength: "100" });
  const enabled = el("input", { type: "checkbox", name: "enabled", checked: true });
  const queryParams = el("input", { name: "queryParams", placeholder: "q, limit, page" });

  const reads = el("div", { className: "choices", role: "group", "aria-label": "APIs the agent may read" });
  for (const c of s.credentials) {
    const box = el("input", { type: "checkbox", value: c.id, "data-credential": c.id });
    reads.append(el("label", { className: "check" }, [box, el("span", {}, [text(c.id), el("span", { className: "hint", text: ` · GET ${new URL(c.baseUrl).host}` })])]));
  }
  const noApis = s.credentials.length === 0 ? el("p", { className: "hint", text: "No API in the policy yet. The agent can be added now and connected to APIs later." }) : null;

  form.append(
    el("div", { className: "form-grid" }, [
      el("label", { className: "field" }, [text("Agent id"), idInput, el("span", { className: "hint", id: "agentIdHint", text: "Lowercase letters, digits, dots and dashes. The broker is started with BROKER_AGENT_ID set to this." })]),
      el("label", { className: "field" }, [text("Display name"), displayName]),
      el("label", { className: "check full" }, [enabled, text("Enabled. Untick to add it now but refuse every request until you enable it in the policy.")]),
      el("div", { className: "field full" }, [text("APIs it may read"), noApis, reads, el("span", { className: "hint", text: "Nothing is ticked by default: a new agent can reach nothing until you choose. Read access only (GET under the API's base URL); write access stays a hand-written policy decision." })]),
      el("label", { className: "field full" }, [text("Query parameters it may use (optional)"), queryParams, el("span", { className: "hint", text: "Applies to every API ticked above. Any query parameter not listed is refused." })]),
    ]),
    result,
  );

  const submit = el("button", { type: "submit", className: "btn primary", text: "Add agent" });
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const qp = queryParams.value.split(",").map((x) => x.trim()).filter(Boolean);
    const chosen = [...reads.querySelectorAll<HTMLInputElement>("input[data-credential]:checked")].map((b) => ({ credentialId: b.value, queryParams: qp }));
    const id = idInput.value.trim();
    void busy(submit, () =>
      api("/api/agent", { id, displayName: displayName.value.trim(), enabled: enabled.checked, reads: chosen })
        .then(() => {
          closeDrawer?.();
          toast(`Added agent ${id}${chosen.length ? ` with read access to ${chosen.length} ${chosen.length === 1 ? "API" : "APIs"}.` : " with no access yet."}`);
          return refresh().then(() => go("agents", id));
        })
        .catch((err: Error) => say(result, "bad", err.message)),
    );
  });
  submit.addEventListener("click", () => form.requestSubmit());
  openDrawer("Add agent", [el("p", { className: "hint", text: "An agent is one broker process with its own identity. It gets a deny-by-default entry in the policy; no key is involved here." }), form], [submit]);
  idInput.focus();
}

// ---- approvals -------------------------------------------------------------------------

function renderApprovals(): Child[] {
  if (!state) return [];
  const s = state;
  const create = el("div", { className: "card-body" });
  if (!s.approvable.length) {
    create.append(el("p", { className: "hint", text: "No operation in the policy requires an approval, so there is nothing to approve. Mark a mutation with requires_approval: true in the policy to use this." }));
  } else {
    const pick = el("select", { "aria-label": "Operation to approve" });
    s.approvable.forEach((o, i) => pick.append(el("option", { value: String(i), text: `${o.agentId} \u00b7 ${o.credentialId} \u00b7 ${o.method} ${o.path} (${o.operationId})` })));
    const minutes = el("input", { type: "number", min: "1", max: "1440", value: "30", "aria-label": "Minutes until the approval expires" });
    const go_ = el("button", { type: "button", className: "btn primary", text: "Create approval" });
    const out = el("div", { className: "result", role: "status" });
    go_.addEventListener("click", () => {
      const o = s.approvable[Number(pick.value)];
      if (!o) return;
      void busy(go_, () =>
        api<{ approvalId: string; expiresAt: string }>("/api/approvals/create", { agentId: o.agentId, credentialId: o.credentialId, operationId: o.operationId, minutes: Number(minutes.value) })
          .then(async (r) => {
            await refresh();
            byId("page").prepend(
              el("div", { className: "banner info", role: "status" }, [
                el("div", { className: "grow" }, [text("Give the agent this approval id: "), el("span", { className: "mono", text: r.approvalId }), el("div", { className: "hint", text: `Valid until ${r.expiresAt}. It covers that one operation for that one agent.` })]),
              ]),
            );
          })
          .catch((e: Error) => say(out, "bad", e.message)),
      );
    });
    create.append(el("div", { className: "row" }, [pick, el("label", { className: "hint" }, [text("Minutes "), minutes]), go_]), out);
  }
  const rows = sortRows(s.approvals, (a) => -Date.parse(a.expiresAt), "asc");
  const tbody = el("tbody");
  for (const a of rows) {
    const revoke = a.state === "active" ? el("button", { type: "button", className: "btn small ghost danger", text: "Revoke" }) : null;
    revoke?.addEventListener("click", () => void busy(revoke, () => api("/api/approvals/revoke", { approvalId: a.id }).then(() => refresh())));
    tbody.append(
      el("tr", { "aria-selected": current.item === a.id ? "true" : "false" }, [
        el("td", { className: "mono", text: a.id }),
        el("td", { text: a.agentId }),
        el("td", { text: `${a.credentialId} \u00b7 ${a.operationId}` }),
        el("td", { className: "num muted", text: a.expiresAt }),
        el("td", {}, [el("span", { className: `pill ${a.state === "active" ? "ok" : a.state === "revoked" ? "bad" : ""}`, text: a.state })]),
        el("td", {}, [revoke]),
      ]),
    );
  }
  const table = el("table", { className: "data plain" }, [el("thead", {}, [el("tr", {}, ["Id", "Agent", "Operation", "Until", "State", ""].map((h) => el("th", { scope: "col", text: h })))]), tbody]);
  return [
    pageHead("Approvals", "An approval unlocks one state-changing operation for one agent for a limited time. It never widens the policy and it is checked at execution time."),
    el("div", { className: "stack" }, [
      el("div", { className: "card" }, [el("div", { className: "card-head" }, [el("h2", { text: "Create an approval" })]), create]),
      el("div", { className: "card" }, [rows.length ? el("div", { className: "table-wrap" }, [table]) : el("div", { className: "empty" }, [el("strong", { text: "No approvals yet." })])]),
    ]),
  ];
}

// ---- activity ---------------------------------------------------------------------------

const activityFilter: ActivityFilter = { ...EMPTY_FILTER };
let activityCache: ActivityRecord[] | null = null;

function renderActivity(): Child[] {
  if (!state) return [];
  const s = state;
  const holder = el("div", { className: "card" }, [el("div", { className: "empty" }, [el("span", { text: "Loading\u2026" })])]);
  const select = (label: string, options: string[], key: "agent" | "credential" | "outcome", current_: string): HTMLSelectElement => {
    const sel = el("select", { "aria-label": label }, [el("option", { value: "", text: label }), ...options.map((o) => el("option", { value: o, text: o }))]);
    sel.value = current_;
    sel.addEventListener("change", () => {
      activityFilter[key] = sel.value;
      paint();
    });
    return sel;
  };
  const hours = el("select", { "aria-label": "Time window" }, [
    el("option", { value: "0", text: "All time" }), el("option", { value: "1", text: "Last hour" }), el("option", { value: "24", text: "Last 24 hours" }), el("option", { value: "168", text: "Last 7 days" }), el("option", { value: "720", text: "Last 30 days" }),
  ]);
  hours.value = String(activityFilter.hours);
  hours.addEventListener("change", () => {
    activityFilter.hours = Number(hours.value);
    paint();
  });
  const exportBtn = el("button", { type: "button", className: "btn", text: "Export CSV" });
  const agentSel = select("Any agent", [...new Set((activityCache ?? []).map((r) => r.agentId))].sort(), "agent", activityFilter.agent);
  const credSel = select("Any key", [...new Set((activityCache ?? []).map((r) => r.credentialId))].filter((x) => x !== "-").sort(), "credential", activityFilter.credential);
  const outcomeSel = select("Any outcome", ["succeeded", "denied", "failed", "indeterminate", "requested", "approved", "executing"], "outcome", activityFilter.outcome);
  const count = el("span", { className: "hint num" });
  const toolbar = el("div", { className: "toolbar" }, [el("div", { className: "right" }, [agentSel, credSel, outcomeSel, hours]), el("div", { className: "right" }, [count, exportBtn])]);

  const paint = (): void => {
    const records = filterActivity(activityCache ?? [], activityFilter);
    count.textContent = `${records.length} of ${activityCache?.length ?? 0}`;
    if (!records.length) {
      holder.replaceChildren(el("div", { className: "empty" }, [el("strong", { text: "No activity matches." }), el("span", { text: "The audit log records who reached what and the outcome, never the content." })]));
      return;
    }
    const tbody = el("tbody");
    for (const r of records.slice(0, 500)) {
      const outcomeKind = r.outcome === "succeeded" ? "ok" : r.outcome === "denied" || r.outcome === "failed" ? "bad" : "";
      tbody.append(
        el("tr", {}, [
          el("td", { className: "num muted", text: r.at.replace("T", " ").replace(/\.\d+Z$/u, "Z") }),
          el("td", { text: r.agentId }),
          el("td", { text: r.credentialId === "-" ? "" : r.credentialId }),
          el("td", {}, [el("span", { className: "mono", text: r.method }), el("span", { className: "sub", text: r.host === "broker.local" ? r.pathname : `${r.host}${r.pathname}` })]),
          el("td", {}, [el("span", { className: `pill ${outcomeKind}`, text: r.outcome })]),
          el("td", { className: "num muted", text: r.status === null ? "" : String(r.status) }),
        ]),
      );
    }
    const parts: Node[] = [el("div", { className: "table-wrap" }, [el("table", { className: "data plain" }, [el("thead", {}, [el("tr", {}, ["When", "Agent", "Key", "What", "Outcome", "Status"].map((h) => el("th", { scope: "col", text: h })))]), tbody])])];
    if (records.length > 500) parts.push(el("p", { className: "hint", text: "Showing the newest 500. Narrow the filters or export the CSV for the rest." }));
    holder.replaceChildren(...parts);
  };
  exportBtn.addEventListener("click", () => {
    const records = filterActivity(activityCache ?? [], activityFilter);
    const csv = toCsv(["at", "agent", "credential", "method", "host", "path", "outcome", "status"], records.map((r) => [r.at, r.agentId, r.credentialId, r.method, r.host, r.pathname, r.outcome, r.status]));
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = el("a", { href: url, download: `credential-broker-activity-${new Date().toISOString().slice(0, 10)}.csv` });
    document.body.append(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Exported ${records.length} rows.`);
  });

  void api<{ records: ActivityRecord[] }>("/api/activity")
    .then(({ records }) => {
      activityCache = records;
      for (const [sel, values] of [[agentSel, records.map((r) => r.agentId)], [credSel, records.map((r) => r.credentialId).filter((x) => x !== "-")]] as const) {
        const keep = sel.value;
        const first = sel.options[0];
        sel.replaceChildren(first ?? el("option", { value: "", text: "" }), ...[...new Set(values)].sort().map((v) => el("option", { value: v, text: v })));
        sel.value = keep;
      }
      paint();
    })
    .catch((e: Error) => holder.replaceChildren(el("div", { className: "empty" }, [el("span", { className: "result bad", text: e.message })])));

  return [pageHead("Activity", `From ${s.register.auditFile}. Content-free by design: who reached what, when, with what outcome. Never what they saw.`), toolbar, holder];
}

// ---- import ----------------------------------------------------------------------------

interface ScanRow {
  rowId: string;
  name: string;
  suggestedId: string;
  preset: { label: string } | null;
  sources: { where: string; path: string }[];
  alreadyStoredAs: string | null;
  idTaken: boolean;
  sensitive: boolean;
  ui?: { check: HTMLInputElement; idInput: HTMLInputElement; mode: HTMLSelectElement; status: HTMLElement };
}

let scanRows: ScanRow[] = [];

function renderImport(): Child[] {
  if (!state) return [];
  const s = state;
  const result = el("div", { className: "result", role: "status" });
  const rowsHost = el("div", { className: "list" });
  const area = el("div", { className: "stack", hidden: scanRows.length === 0 });
  const agentSel = el("select", { "aria-label": "Agent to give read access" }, [...s.agents.map((a) => el("option", { value: a.id, text: a.id })), el("option", { value: "__new", text: "New agent\u2026" }), el("option", { value: "__none", text: "Nobody yet" })]);
  const newAgent = el("input", { placeholder: "claude", pattern: "[a-z0-9][a-z0-9._-]{1,63}", hidden: true, "aria-label": "New agent name" });
  agentSel.addEventListener("change", () => {
    newAgent.hidden = agentSel.value !== "__new";
  });
  if (!s.agents.length) {
    agentSel.value = "__new";
    newAgent.hidden = false;
  }
  const scan = el("button", { type: "button", className: "btn primary", text: scanRows.length ? "Search again" : "Find my keys" });
  const importGo = el("button", { type: "button", className: "btn primary", text: "Import selected" });

  const paintRows = (): void => {
    rowsHost.replaceChildren();
    if (!scanRows.length) {
      rowsHost.append(el("p", { className: "hint", text: "No keys found in the usual places." }));
      return;
    }
    for (const r of scanRows) {
      const check = el("input", { type: "checkbox", "aria-label": `Import ${r.name}` });
      check.checked = !r.alreadyStoredAs && !r.sensitive;
      const idInput = el("input", { type: "text", value: r.suggestedId, spellcheck: "false", "aria-label": `Short name for ${r.name}` });
      const mode = el("select", { "aria-label": `What to do with ${r.name}` });
      if (r.preset) mode.append(el("option", { value: "api", text: `Add as ${r.preset.label} API` }));
      mode.append(el("option", { value: "store", text: "Store only" }));
      const where = r.sources.map((x) => `${x.where}${x.path ? `: ${x.path}` : ""}`).join(" \u00b7 ");
      let flag: HTMLElement | null = null;
      if (r.sensitive) flag = el("span", { className: "pill bad", text: "Looks like a wallet key. Store only; never give an agent this." });
      else if (r.alreadyStoredAs) flag = el("span", { className: "pill ok", text: `Already saved as ${r.alreadyStoredAs}` });
      else if (r.idTaken) flag = el("span", { className: "pill warn", text: "That short name is taken; change it before importing." });
      const status = el("div", { className: "result" });
      r.ui = { check, idInput, mode, status };
      rowsHost.append(
        el("div", { className: "list-row" }, [
          el("label", { className: "check" }, [check, el("span", {}, [el("div", { className: "name", text: r.name }), el("div", { className: "meta", text: where }), flag, status])]),
          el("div", { className: "row" }, [idInput, mode]),
        ]),
      );
    }
  };
  scan.addEventListener("click", () => {
    scan.textContent = "Searching\u2026 (about 10 seconds)";
    void busy(scan, () =>
      api<{ rows: ScanRow[] }>("/api/import/scan")
        .then((data) => {
          scanRows = data.rows;
          area.hidden = false;
          say(result, "", "");
          paintRows();
        })
        .catch((e: Error) => say(result, "bad", e.message))
        .finally(() => {
          scan.textContent = "Search again";
        }),
    );
  });
  importGo.addEventListener("click", () => {
    const picked = scanRows.filter((r) => r.ui?.check.checked);
    if (!picked.length) {
      say(result, "warn", "Tick at least one key.");
      return;
    }
    const agentId = agentSel.value === "__none" ? null : agentSel.value === "__new" ? newAgent.value.trim() || "claude" : agentSel.value;
    const body = { agentId, items: picked.map((r) => ({ rowId: r.rowId, id: r.ui?.idInput.value.trim() ?? "", mode: r.ui?.mode.value ?? "store" })) };
    void busy(importGo, () =>
      api<{ results: { rowId: string; ok: boolean; message: string; test?: { path: string; status: number } }[] }>("/api/import/apply", body)
        .then((data) => {
          let ok = 0;
          for (const res of data.results) {
            const row = scanRows.find((r) => r.rowId === res.rowId);
            if (!row?.ui) continue;
            let message = res.message;
            let kind: "ok" | "bad" | "warn" = res.ok ? "ok" : "bad";
            if (res.test) {
              const [k, m] = explainStatus(res.test.status);
              message += ` Test ${res.test.path}: ${m}`;
              if (k !== "ok") kind = "warn";
            }
            if (res.ok) {
              ok += 1;
              row.ui.check.checked = false;
            }
            say(row.ui.status, kind, message);
          }
          say(result, ok === data.results.length ? "ok" : "warn", `${ok} of ${data.results.length} imported. The original copies are untouched; delete them yourself once you are happy. Restart the MCP client so the broker loads the new keys.`);
          return refresh();
        })
        .catch((e: Error) => say(result, "bad", e.message)),
    );
  });
  if (scanRows.length) paintRows();
  area.append(rowsHost, el("div", { className: "row" }, [el("label", { className: "hint" }, [text("Give read access to new APIs: "), agentSel]), newAgent]), el("div", { className: "row" }, [importGo]));
  return [
    pageHead("Import", "Looks in your user environment variables, MCP client configs (Claude Code, Claude Desktop, Cursor) and .env files under Documents and C:\\Dev. Keys are read by the key manager itself and never shown here. Your original copies are left exactly as they are."),
    el("div", { className: "card" }, [el("div", { className: "card-body stack" }, [el("div", { className: "row" }, [scan]), result, area])]),
  ];
}

// ---- settings ------------------------------------------------------------------------------

let connectionClient = "claude";
let connectionAgent = "";

function renderSettings(): Child[] {
  if (!state) return [];
  const s = state;
  const clientSel = el("select", { "aria-label": "Client", "data-fid": "connectClient" }, [
    el("option", { value: "claude", text: "Claude Code" }),
    el("option", { value: "codex", text: "Codex" }),
  ]);
  clientSel.value = connectionClient;
  const agentSel = el("select", { "aria-label": "Agent", "data-fid": "connectAgent" }, s.agents.map((a) => el("option", { value: a.id, text: a.id })));
  if (s.agents.some((a) => a.id === connectionAgent)) agentSel.value = connectionAgent;
  const cmd = el("pre", { id: "connectCmd" });
  const instructions = el("p", { className: "hint" });
  const copy = el("button", { type: "button", className: "btn", text: "Copy" });
  const paintCmd = (): void => {
    const codex = clientSel.value === "codex";
    const r = s.register;
    instructions.textContent = codex
      ? "Add this block to your Codex config.toml, or update the existing credential-broker entry. The same setup works in local ChatGPT desktop sessions on this host. Restart the client after saving."
      : "Run this command in your terminal, then restart Claude Code.";
    copy.disabled = !agentSel.value;
    if (!agentSel.value) {
      cmd.textContent = "Add an agent first.";
    } else if (codex) {
      const q = (value: string): string => JSON.stringify(value);
      cmd.textContent = [
        "[mcp_servers.credential-broker]",
        'command = "node"',
        `args = [${q(r.stdioEntry)}]`,
        "",
        "[mcp_servers.credential-broker.env]",
        `BROKER_AGENT_ID = ${q(agentSel.value)}`,
        `BROKER_POLICY_FILE = ${q(r.policyFile)}`,
        `BROKER_AUDIT_FILE = ${q(r.auditFile)}`,
        `BROKER_APPROVALS_FILE = ${q(r.approvalsFile)}`,
        `BROKER_PAUSE_FILE = ${q(r.pauseFile)}`,
        `BROKER_RELOAD_MARKER = ${q(r.reloadMarker)}`,
      ].join("\n");
    } else {
      const q = (value: string): string => `"${value}"`;
      cmd.textContent = `claude mcp add credential-broker --scope user -e BROKER_AGENT_ID=${agentSel.value} -e BROKER_POLICY_FILE=${q(r.policyFile)} -e BROKER_AUDIT_FILE=${q(r.auditFile)} -e BROKER_APPROVALS_FILE=${q(r.approvalsFile)} -e BROKER_PAUSE_FILE=${q(r.pauseFile)} -e BROKER_RELOAD_MARKER=${q(r.reloadMarker)} -- node ${q(r.stdioEntry)}`;
    }
  };
  clientSel.addEventListener("change", () => {
    connectionClient = clientSel.value;
    paintCmd();
  });
  agentSel.addEventListener("change", () => {
    connectionAgent = agentSel.value;
    paintCmd();
  });
  paintCmd();
  copy.addEventListener("click", () => {
    void navigator.clipboard.writeText(cmd.textContent ?? "").then(() => {
      copy.textContent = "Copied";
      window.setTimeout(() => {
        copy.textContent = "Copy";
      }, 1500);
    }).catch(() => toast("Could not copy. Select and copy the setup text manually."));
  });
  const themeSel = el("select", { "aria-label": "Theme" }, [el("option", { value: "system", text: "Follow the system" }), el("option", { value: "light", text: "Light" }), el("option", { value: "dark", text: "Dark" })]);
  themeSel.value = readTheme();
  themeSel.addEventListener("change", () => {
    try {
      localStorage.setItem(THEME_KEY, themeSel.value);
    } catch {
      // Not remembered, still applied.
    }
    applyTheme(themeSel.value as Theme);
  });
  const close = el("button", { type: "button", className: "btn danger", text: "Close the key manager" });
  close.addEventListener("click", () => {
    void api("/api/close").finally(() => {
      document.body.replaceChildren(el("main", { className: "page" }, [el("h1", { text: "Key manager closed." }), el("p", { className: "hint", text: "Run npm run keys to open it again." })]));
    });
  });
  const paths = el("dl", { className: "kv" }, Object.entries(s.paths).flatMap(([k, v]) => [el("dt", { text: k.replace(/File$|Marker$/u, (m) => ` ${m.toLowerCase()}`) }), el("dd", { text: v })]));
  return [
    pageHead("Settings", "Where things live, how to connect an agent, and how this page looks."),
    el("div", { className: "stack" }, [
      el("div", { className: "card" }, [
        el("div", { className: "card-head" }, [el("h2", { text: "Connect an MCP client" })]),
        el("div", { className: "card-body stack" }, [
          el("div", { className: "row" }, [el("label", { className: "hint" }, [text("Client "), clientSel]), el("label", { className: "hint" }, [text("Agent "), agentSel]), copy]),
          instructions,
          cmd,
          el("p", { className: "hint", text: "The setup includes paths and an agent ID. The broker loads credentials at startup. After changing a key, restart the client or enable BROKER_HOT_RELOAD=1." }),
        ]),
      ]),
      el("div", { className: "card" }, [el("div", { className: "card-head" }, [el("h2", { text: "Files" })]), el("div", { className: "card-body" }, [paths])]),
      el("div", { className: "card" }, [
        el("div", { className: "card-head" }, [el("h2", { text: "This page" })]),
        el("div", { className: "card-body stack" }, [
          el("div", { className: "row" }, [el("label", { className: "hint" }, [text("Theme "), themeSel])]),
          el("dl", { className: "kv" }, [el("dt", { text: "Version" }), el("dd", { text: s.version || "unknown" }), el("dt", { text: "Keychain" }), el("dd", { text: s.keychain ?? "none (environment variables only)" }), el("dt", { text: "Platform" }), el("dd", { text: s.platform }), el("dt", { text: "Shortcuts" }), el("dd", { text: "/ or Ctrl+K to search, Esc to close a panel" })]),
          el("div", { className: "row" }, [close]),
        ]),
      ]),
    ]),
  ];
}

// ---- boot -------------------------------------------------------------------------------------

function applyLaunchPrefill(): void {
  if (!launchPrefill || !state) return;
  const p = launchPrefill;
  launchPrefill = null;
  const existing = state.credentials.find((c) => c.id === p.id);
  if (existing) {
    byId("banners").prepend(
      el("div", { className: "banner warn", role: "alert" }, [el("div", { className: "grow" }, [el("strong", { text: `${p.requestedBy ?? "An agent"} asked for a key called ${p.id}.` }), el("div", { text: p.reason ? `Reason given: ${p.reason}` : "No reason given." }), el("div", { className: "hint", text: "That API already exists. Paste its key in the panel if you agree." })])]),
    );
    go("keys", p.id);
    return;
  }
  openNewKey({ prefill: p });
}

function boot(): void {
  applyTheme(readTheme());
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(readTheme()));
  byId("theme").addEventListener("click", cycleTheme);
  byId("newKey").addEventListener("click", () => openNewKey({}));
  byId("pauseBtn").addEventListener("click", (e) => {
    const button = e.currentTarget as HTMLButtonElement;
    if (!state) return;
    const paused = !!state.pause.all || state.pause.unreadable;
    void busy(button, () => pauseAll(!paused)).then(() => button.focus());
  });
  setupSearch();
  setupMenu();
  window.addEventListener("hashchange", onRoute);
  if (!token) {
    renderFatal("Missing session token. Open the link printed by npm run keys.");
    return;
  }
  current = parseRoute(location.hash);
  if (!(PAGES as readonly string[]).includes(current.page)) current = { page: "overview", item: null };
  void refresh().then(() => applyLaunchPrefill());
}

boot();
