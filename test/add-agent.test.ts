import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { addAgentToPolicy } from "../src/policy-edit.js";
import { parseBrokerPolicy } from "../src/policy.js";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..", "..");
const distSrc = join(packageRoot, "dist", "src");

const BASE = `# operator comment that must survive
version: 2
credentials:
  - id: github
    kind: bearer
    env_var: GITHUB_TOKEN
    base_url: https://api.github.com
  - id: weather
    kind: query
    env_var: WEATHER_KEY
    param_name: appid
    base_url: https://api.openweathermap.org
    high_risk: true
groups:
  team: [claude]
agents:
  - id: claude
    grants:
      - credential: github
        operations:
          - id: read-repo
            method: GET
            path: /repos/*/*
`;

void test("addAgentToPolicy adds a deny-by-default agent, keeps comments, and only ever writes read grants", () => {
  const text = addAgentToPolicy(BASE, { id: "codex", displayName: "Codex", enabled: true, reads: [] });
  assert.match(text, /# operator comment that must survive/u);
  const policy = parseBrokerPolicy(text);
  const codex = policy.agents.get("codex");
  assert.equal(codex?.displayName, "Codex");
  assert.equal(codex?.enabled, true);
  assert.equal(codex?.grants.size, 0, "no grants unless chosen");
  assert.equal(policy.agents.get("claude")?.grants.get("github")?.operations[0]?.id, "read-repo", "existing agents untouched");

  const withReads = parseBrokerPolicy(addAgentToPolicy(BASE, { id: "grok", displayName: "", enabled: false, reads: [{ credentialId: "weather", queryParams: ["q", "units"] }] }));
  const grok = withReads.agents.get("grok");
  assert.equal(grok?.displayName, "grok", "display name falls back to the id");
  assert.equal(grok?.enabled, false);
  const ops = grok?.grants.get("weather")?.operations ?? [];
  assert.equal(ops.length, 1);
  assert.equal(ops[0]?.method, "GET");
  assert.deepEqual(ops[0]?.pathTemplate, ["**"]);
  assert.deepEqual(ops[0]?.queryParams, ["q", "units"]);
  assert.equal(ops[0]?.requiresApproval, false);
  assert.equal(grok?.grants.has("github"), false);
});

void test("addAgentToPolicy refuses duplicates, group-name clashes, unknown APIs and a missing policy", () => {
  assert.throws(() => addAgentToPolicy(BASE, { id: "claude", displayName: "", enabled: true, reads: [] }), /already exists/u);
  assert.throws(() => addAgentToPolicy(BASE, { id: "team", displayName: "", enabled: true, reads: [] }), /already a group name/u);
  assert.throws(() => addAgentToPolicy(BASE, { id: "x1", displayName: "", enabled: true, reads: [{ credentialId: "ghost", queryParams: [] }] }), /No API named 'ghost'/u);
  assert.throws(() => addAgentToPolicy(BASE, { id: "x1", displayName: "", enabled: true, reads: [{ credentialId: "github", queryParams: [] }, { credentialId: "github", queryParams: [] }] }), /selected twice/u);
  assert.throws(() => addAgentToPolicy(null, { id: "x1", displayName: "", enabled: true, reads: [] }), /Add a key first/u);
  assert.throws(() => addAgentToPolicy("version: [", { id: "x1", displayName: "", enabled: true, reads: [] }), /not valid YAML/u);
});

void test("the key manager adds an agent through the policy-save path: validated, backed up, reload marker touched, no secret involved", async () => {
  const dir = await mkdtemp(join(tmpdir(), "broker-agent-"));
  const policyFile = join(dir, "broker.yaml");
  const auditFile = join(dir, "audit.jsonl");
  await writeFile(policyFile, BASE);
  const env = { ...process.env, BROKER_POLICY_FILE: policyFile, BROKER_AUDIT_FILE: auditFile, BROKER_KEYCHAIN: "off", BROKER_KEYS_PORT: "0" };
  const child = spawn(process.execPath, [join(distSrc, "keys-ui.js"), "--no-open"], { env, stdio: "pipe", windowsHide: true });
  try {
    const url = await new Promise<string>((resolveUrl, reject) => {
      let out = "";
      child.stdout.on("data", (chunk: Buffer) => {
        out += chunk.toString();
        const hit = /Open:\s+(http:\/\/127\.0\.0\.1:\d+\/#[0-9a-f]+)/u.exec(out);
        if (hit?.[1]) resolveUrl(hit[1]);
      });
      child.on("error", reject);
      child.on("close", (code) => reject(new Error(`key manager exited early (${code})`)));
    });
    const base = url.split("#")[0] ?? "";
    const token = url.split("#")[1] ?? "";
    const call = async (path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> => {
      const res = await fetch(`${base}api/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      return { status: res.status, json: (await res.json()) as Record<string, unknown> };
    };

    const bad = await call("agent", { id: "claude", reads: [] });
    assert.equal(bad.status, 400);
    assert.match(String(bad.json["error"]), /already exists/u);
    assert.equal(await readFile(policyFile, "utf8"), BASE, "a refused request writes nothing");

    const badApi = await call("agent", { id: "codex", reads: [{ credentialId: "ghost" }] });
    assert.equal(badApi.status, 400);
    assert.match(String(badApi.json["error"]), /No API named/u);

    const ok = await call("agent", { id: "codex", displayName: "Codex", enabled: true, reads: [{ credentialId: "github", queryParams: ["per_page"] }] });
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
    assert.deepEqual(ok.json, { ok: true, agentId: "codex", reads: 1 });

    const written = await readFile(policyFile, "utf8");
    assert.match(written, /# operator comment that must survive/u);
    const policy = parseBrokerPolicy(written);
    assert.deepEqual([...policy.agents.keys()], ["claude", "codex"]);
    assert.deepEqual(policy.agents.get("codex")?.grants.get("github")?.operations[0]?.queryParams, ["per_page"]);
    assert.ok(existsSync(`${policyFile}.bak`), "the previous policy is kept as a backup");
    assert.equal(readFileSync(`${policyFile}.bak`, "utf8"), BASE);
    assert.ok(existsSync(join(dir, ".broker-reload")), "the hot-reload marker is touched");

    const state = await call("state", {});
    assert.equal(state.status, 200);
    const agents = state.json["agents"] as { id: string; displayName: string; enabled: boolean }[];
    assert.deepEqual(agents.find((a) => a.id === "codex"), { id: "codex", displayName: "Codex", enabled: true });
    assert.doesNotMatch(JSON.stringify(state.json), /GITHUB_TOKEN_VALUE/u);
  } finally {
    child.kill();
    await rm(dir, { recursive: true, force: true });
  }
});

void test("the page's header carries the navigation, a menu button for narrow screens, and the actions on the right", () => {
  const html = readFileSync(join(packageRoot, "src", "ui", "index.html"), "utf8");
  const header = /<header class="top"[^>]*>([\s\S]*?)<\/header>/u.exec(html)?.[1] ?? "";
  assert.ok(header.length > 0);
  assert.match(header, /<nav class="nav" aria-label="Pages" id="tabs">/u, "the nav sits inside the header bar");
  assert.doesNotMatch(html.replace(header, ""), /<nav/u, "and nowhere else");
  for (const page of ["overview", "keys", "agents", "approvals", "activity", "import", "settings"]) {
    assert.match(header, new RegExp(`<a href="#/${page}" data-page="${page}">`, "u"));
  }
  assert.match(header, /<button id="menuBtn"[^>]*aria-expanded="false"[^>]*aria-controls="tabs"/u, "the menu button controls the nav");
  const order = ["id=\"menuBtn\"", "class=\"brand\"", "id=\"tabs\"", "id=\"searchWrap\"", "id=\"statusChip\"", "id=\"pauseBtn\"", "id=\"newKey\""].map((m) => header.indexOf(m));
  assert.deepEqual([...order].sort((a, b) => a - b), order, "menu, brand, pages, search, then status, pause and New key on the right");
  const css = readFileSync(join(packageRoot, "src", "ui", "app.css"), "utf8");
  assert.match(css, /@media \(max-width: 1200px\) \{[\s\S]*?\.btn\.menu \{ display: inline-flex; \}/u, "the menu button appears on narrow screens");
  assert.match(css, /\.btn\.menu \{ display: none; \}/u, "and is hidden on wide ones");
});
