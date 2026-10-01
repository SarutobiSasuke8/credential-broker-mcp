import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { parseDotenv, scanForKeys } from "../src/import-scan.js";

void test("parseDotenv handles quotes, export, and trailing comments", () => {
  const parsed = parseDotenv(
    [
      "export A_KEY=plain",
      'B_TOKEN="quoted value" # note',
      "C_SECRET='single'",
      "D_KEY=unquoted # comment",
      "# E_KEY=commented-out",
      "EMPTY_KEY=",
    ].join("\n"),
  );
  assert.equal(parsed.get("A_KEY"), "plain");
  assert.equal(parsed.get("B_TOKEN"), "quoted value");
  assert.equal(parsed.get("C_SECRET"), "single");
  assert.equal(parsed.get("D_KEY"), "unquoted");
  assert.equal(parsed.has("E_KEY"), false);
  assert.equal(parsed.has("EMPTY_KEY"), false);
});

void test("scan finds keys, merges duplicates, splits different values, and skips public ones", async () => {
  const root = await mkdtemp(join(tmpdir(), "cb-scan-"));
  try {
    await mkdir(join(root, "app-one"));
    await mkdir(join(root, "app-two"));
    await mkdir(join(root, "app-two", "node_modules", "dep"), { recursive: true });
    await writeFile(join(root, "app-one", ".env"), "GEMINI_API_KEY=same-gemini\nNEXT_PUBLIC_MAP_KEY=public\nPORT=3000\n");
    await writeFile(join(root, "app-two", ".env.local"), "GEMINI_API_KEY=other-gemini\nOPENROUTER_API_KEY=or-1\nPRIVATE_KEY=0xabc\n");
    await writeFile(join(root, "app-two", ".env.example"), "OPENROUTER_API_KEY=placeholder\n");
    await writeFile(join(root, "app-two", "node_modules", "dep", ".env"), "LEAKY_TOKEN=nope\n");
    const mcp = join(root, "claude.json");
    await writeFile(
      mcp,
      JSON.stringify({
        mcpServers: { pixellab: { type: "http", url: "https://api.pixellab.ai/mcp", headers: { Authorization: "Bearer px-1" } } },
        projects: { "C:/x/proj": { mcpServers: { tool: { env: { TOOL_API_KEY: "tool-1", LOG_LEVEL: "debug" } } } } },
      }),
    );

    const rows = await scanForKeys({
      roots: [root],
      mcpConfigs: [mcp, join(root, "missing.json")],
      userEnvironment: () => Promise.resolve({ GEMINI_API_KEY: "same-gemini", PATH: "C:/bin" }),
    });
    const byId = new Map(rows.map((r) => [r.suggestedId, r]));

    // Same Gemini value in the user env and app-one is one row with two sources.
    const shared = rows.find((r) => r.value === "same-gemini");
    assert.equal(shared?.sources.length, 2);
    // A different Gemini value is its own row, and the ids are told apart.
    const other = rows.find((r) => r.value === "other-gemini");
    assert.ok(other && shared && other.suggestedId !== shared.suggestedId);
    assert.equal(other?.preset?.id, "gemini");

    assert.equal(byId.get("openrouter")?.value, "or-1");
    assert.equal(byId.get("pixellab")?.value, "px-1", "Bearer prefix stripped from MCP headers");
    assert.equal(byId.get("tool-api-key")?.value, "tool-1");

    const wallet = rows.find((r) => r.name === "PRIVATE_KEY");
    assert.equal(wallet?.sensitive, true);
    assert.equal(wallet?.preset, null);

    const names = rows.map((r) => r.name);
    for (const skipped of ["NEXT_PUBLIC_MAP_KEY", "PORT", "LEAKY_TOKEN", "LOG_LEVEL", "PATH"]) {
      assert.ok(!names.includes(skipped), `${skipped} should be skipped`);
    }
    assert.ok(!rows.some((r) => r.value === "placeholder"), ".env.example files are ignored");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
