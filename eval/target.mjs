#!/usr/bin/env node
// Contract-suite target for mcp-eval. Not shipped, not used by the broker.
//
// Builds a throwaway world in a fresh OS temp directory, then runs the real stdio entrypoint
// (dist/src/stdio.js) against it:
//   - broker.yaml: a throwaway test policy. Agent eval-agent holds one credential,
//     eval-upstream. A second credential, eval-unrelated, is granted only to eval-other, so it
//     exists but is out of scope for eval-agent.
//   - a fake secret, generated fresh on every run. It always starts with FAKESECRET42 (12 bytes,
//     so its Base64 form always starts with RkFLRVNFQ1JFVDQy), which lets the suite assert with
//     a regex that no result ever carries it. It reaches the broker only through its env var.
//   - audit.jsonl and approvals.json in the same temp directory.
//   - an upstream on 127.0.0.1:47391 (loopback only, no outside network) that deliberately
//     echoes the injected Authorization header and the Base64 of the secret back in its
//     response body, so the broker's redaction is exercised on a real response.
// The child gets a minimal environment (no inherited shell secrets), and the temp directory is
// removed when the broker exits.
import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { URL, fileURLToPath } from "node:url";

const UPSTREAM_PORT = 47391;
const here = path.dirname(fileURLToPath(import.meta.url));
const stdioEntry = path.resolve(here, "..", "dist", "src", "stdio.js");

const dir = mkdtempSync(path.join(tmpdir(), "credential-broker-eval-"));
const policyFile = path.join(dir, "broker.yaml");
const auditFile = path.join(dir, "audit.jsonl");
const approvalsFile = path.join(dir, "approvals.json");
const fakeSecret = `FAKESECRET42${randomBytes(18).toString("hex")}`;

writeFileSync(policyFile, `# Throwaway contract-suite policy. Synthetic ids, loopback upstream, fake secret.
version: 2

credentials:
  - id: eval-upstream
    description: Synthetic bearer credential for the contract suite
    kind: bearer
    env_var: CB_EVAL_UPSTREAM_TOKEN
    base_url: http://127.0.0.1:${UPSTREAM_PORT}/api

  - id: eval-unrelated
    description: Synthetic credential granted to a different agent only
    kind: bearer
    env_var: CB_EVAL_UNRELATED_TOKEN
    base_url: http://127.0.0.1:${UPSTREAM_PORT}/other

agents:
  - id: eval-agent
    display_name: Eval Agent
    enabled: true
    max_response_bytes: 65536
    grants:
      - credential: eval-upstream
        operations:
          - id: read-item
            method: GET
            path: /items/*
            response_body: true
          - id: read-meta
            method: GET
            path: /meta
            response_body: false
          - id: create-item
            method: POST
            path: /items
            body:
              content_types: [application/json]
              max_bytes: 4096
            response_body: true
            requires_approval: true
            requires_idempotency_key: true
        deny:
          - /items/admin

  - id: eval-other
    display_name: Eval Other
    enabled: true
    max_response_bytes: 65536
    grants:
      - credential: eval-unrelated
        operations:
          - id: read-status
            method: GET
            path: /status
            response_body: true
`);
writeFileSync(approvalsFile, "[]\n");

const upstream = createServer((request, response) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${UPSTREAM_PORT}`);
  const item = /^\/api\/items\/([a-z0-9-]+)$/u.exec(url.pathname);
  if (request.method === "GET" && item) {
    const authorization = request.headers.authorization ?? "";
    const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    // A hostile or careless upstream: it reflects the credential back in two encodings.
    const body = JSON.stringify({
      id: item[1],
      name: "Synthetic widget",
      echo_authorization: authorization,
      echo_token_base64: Buffer.from(token, "utf8").toString("base64"),
    });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(body);
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/meta") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ build: "synthetic", echo_authorization: request.headers.authorization ?? "" }));
    return;
  }
  response.writeHead(404, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: "not found" }));
});

function cleanUp() {
  upstream.close();
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // Best effort: the OS temp directory is cleared eventually anyway.
  }
}

upstream.on("error", (error) => {
  process.stderr.write(`Contract-suite upstream could not listen on 127.0.0.1:${UPSTREAM_PORT}: ${error.message}\n`);
  cleanUp();
  process.exit(1);
});

upstream.listen(UPSTREAM_PORT, "127.0.0.1", () => {
  // Minimal environment: nothing from the calling shell beyond what Node needs to start, so a
  // real credential exported in the operator's shell can never reach the broker under test.
  const env = {};
  for (const name of ["PATH", "Path", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE"]) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  const child = spawn(process.execPath, [stdioEntry], {
    stdio: "inherit",
    env: {
      ...env,
      BROKER_AGENT_ID: "eval-agent",
      BROKER_POLICY_FILE: policyFile,
      BROKER_AUDIT_FILE: auditFile,
      BROKER_APPROVALS_FILE: approvalsFile,
      CB_EVAL_UPSTREAM_TOKEN: fakeSecret,
    },
  });
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => child.kill(signal));
  }
  child.on("exit", (code) => {
    cleanUp();
    process.exit(code ?? 1);
  });
});
