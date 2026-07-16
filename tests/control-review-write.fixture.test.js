import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const cliPath = path.join(packageRoot, "dist", "cli.js");
const tenantId = "00000000-0000-4000-8000-000000000001";
const controlId = "00000000-0000-4000-8000-000000000701";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("control request-review is dry-run by default", async () => {
  const result = await runCli(["controls", "request-review", controlId, "--json"], { PATH: process.env.PATH || "" });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, "");
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.ok, true);
  assert.equal(payload.data.dryRun, true);
  assert.equal(payload.data.controlId, controlId);
  assert.equal(payload.data.action, "request-review");
  assert.match(payload.data.writeRequired, new RegExp(`--write --confirm ${controlId}`));
});

test("control request-review writes through the Oneleet control endpoint", async () => {
  const server = await startControlServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-control-review-"));

  try {
    const result = await runCli(
      ["controls", "request-review", controlId, "--write", "--confirm", controlId, "--json"],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.equal(payload.data.control.id, controlId);
    assert.equal(payload.data.control.status, "IN_REVIEW");
    assert.equal(payload.data.control.reviewStatus, "IN_REVIEW");
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `POST /api/v1/controls/${controlId}/request-review`,
      `GET /api/v1/controls/${controlId}`,
    ]);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("control request-review accepts a local control ref without exposing the upstream id", async () => {
  const server = await startControlServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-control-review-local-ref-"));

  try {
    const result = await runCli(
      ["controls", "request-review", "control-001", "--write", "--confirm", "control-001", "--json"],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.deepEqual(payload.data.selector, { mode: "ref", ref: "control-001", hasId: true });
    assert.equal("controlId" in payload.data, false);
    assert.equal(result.stdout.includes(controlId), true);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/tenants/${tenantId}/controls/program`,
      `POST /api/v1/controls/${controlId}/request-review`,
      `GET /api/v1/controls/${controlId}`,
    ]);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

async function startControlServer() {
  const requests = [];
  let submitted = false;

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });

    if (request.method === "GET" && url.pathname === `/api/v1/tenants/${tenantId}/controls/program`) {
      writeJson(response, { rows: [controlFixture(submitted)] });
      return;
    }

    if (request.method === "POST" && url.pathname === `/api/v1/controls/${controlId}/request-review`) {
      submitted = true;
      writeJson(response, { ok: true });
      return;
    }

    if (request.method === "GET" && url.pathname === `/api/v1/controls/${controlId}`) {
      writeJson(response, controlFixture(submitted));
      return;
    }

    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "unexpected fixture path", path: url.pathname }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function controlFixture(submitted) {
  return {
    id: controlId,
    status: submitted ? "IN_REVIEW" : "IN_PROGRESS",
    reviewStatus: submitted ? "IN_REVIEW" : "UNREVIEWED",
    controlType: {
      title: "Audit logs collected",
      category: "MONITORING_AND_INCIDENT_RESPONSE",
    },
    checks: [],
    linkedEvidence: [{ id: "00000000-0000-4000-8000-000000000801" }],
    evidenceRequests: [],
    updatedAt: "2026-06-08T17:30:00.000Z",
  };
}

function writeJson(response, body) {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function fixtureEnv(serverUrl, tempConfigHome) {
  return {
    ONELEET_APP_COOKIE: fakeCookie,
    ONELEET_TENANT_ID: tenantId,
    ONELEET_API_BASE_URL: serverUrl,
    ONELEET_ALLOW_UNSAFE_API_BASE_URL: "1",
    ONELEET_APP_BASE_URL: "http://127.0.0.1/oneleet-app-fixture",
    XDG_CONFIG_HOME: tempConfigHome,
    HOME: tempConfigHome,
    PATH: process.env.PATH || "",
  };
}

function runCli(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      cwd: packageRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
