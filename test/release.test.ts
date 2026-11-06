import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

/**
 * Release plumbing must agree with itself before a tag exists: the npm
 * package, the MCP Registry entry and the binaries the README promises.
 */

const root = new URL("../../", import.meta.url);

async function json(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(new URL(path, root), "utf8")) as Record<string, unknown>;
}

void test("server.json and package.json agree on name, version and package identity", async () => {
  const pkg = await json("package.json");
  const server = await json("server.json");
  assert.equal(server["name"], pkg["mcpName"], "server.json name must equal package.json mcpName");
  assert.match(String(server["name"]), /^io\.github\.[A-Za-z0-9-]+\/[a-z0-9._-]+$/u);
  assert.equal(server["version"], pkg["version"]);
  assert.ok(String(server["description"]).length <= 100, "registry descriptions are capped at 100 characters");
  assert.match(String(server["$schema"]), /^https:\/\/static\.modelcontextprotocol\.io\/schemas\/\d{4}-\d{2}-\d{2}\/server\.schema\.json$/u);

  const packages = server["packages"] as Record<string, unknown>[];
  assert.equal(packages.length, 1);
  const entry = packages[0]!;
  assert.equal(entry["registryType"], "npm");
  assert.equal(entry["identifier"], pkg["name"]);
  assert.equal(entry["version"], pkg["version"]);
  assert.deepEqual(entry["transport"], { type: "stdio" });
  const envVars = entry["environmentVariables"] as Record<string, unknown>[];
  const required = envVars.filter((v) => v["isRequired"] === true).map((v) => v["name"]);
  assert.deepEqual(required, ["BROKER_AGENT_ID"], "only the agent identity is required to start");
  for (const v of envVars) assert.notEqual(v["isSecret"], true, "no broker variable carries a secret value");
});

void test("the package exposes the three binaries the README names, under dist", async () => {
  const pkg = await json("package.json");
  const bin = pkg["bin"] as Record<string, string>;
  assert.deepEqual(Object.keys(bin).sort(), ["credential-broker-keys", "credential-broker-pause", "credential-broker-stdio"]);
  for (const path of Object.values(bin)) assert.match(path, /^dist\/src\/[a-z-]+\.js$/u);
  assert.match(String((pkg["engines"] as Record<string, string>)["node"]), /^>=22/u);
  assert.deepEqual(Object.keys(pkg["dependencies"] as object).sort(), ["@modelcontextprotocol/server", "yaml", "zod"], "three runtime dependencies, on purpose");
});

void test("the changelog has a section for the package version or an Unreleased section", async () => {
  const pkg = await json("package.json");
  const changelog = await readFile(new URL("CHANGELOG.md", root), "utf8");
  assert.ok(changelog.includes(`## ${String(pkg["version"])}`) || changelog.includes("## Unreleased"));
});
