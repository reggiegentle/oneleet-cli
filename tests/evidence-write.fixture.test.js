import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const cliPath = path.join(packageRoot, "dist", "cli.js");
const tenantId = "00000000-0000-4000-8000-000000000001";
const evidenceId = "00000000-0000-4000-8000-000000000101";
const primaryControlId = "00000000-0000-4000-8000-000000000201";
const secondaryControlId = "00000000-0000-4000-8000-000000000202";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("evidence upload is dry-run by default", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-evidence-dry-run-"));
  const evidencePath = path.join(tempDir, "control-evidence.csv");

  try {
    await writeFile(evidencePath, "item,status\nSynthetic Item,attached\n", "utf8");
    const result = await runCli(
      ["evidence", "upload", evidencePath, "--control-id", primaryControlId, "--link-control-id", secondaryControlId, "--json"],
      { PATH: process.env.PATH || "" },
    );

    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, true);
    assert.equal(payload.data.upload.fileName, "control-evidence.csv");
    assert.equal(payload.data.upload.primaryControlId, primaryControlId);
    assert.deepEqual(payload.data.upload.additionalControlIds, [secondaryControlId]);
    assert.match(payload.data.writeRequired, /--write --confirm control-evidence\.csv/);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("evidence upload writes file evidence and links extra controls", async () => {
  const server = await startEvidenceServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-evidence-write-"));
  const evidencePath = path.join(tempDir, "control-evidence.csv");

  try {
    await writeFile(evidencePath, "item,status\nSynthetic Item,attached\n", "utf8");
    const result = await runCli(
      [
        "evidence",
        "upload",
        evidencePath,
        "--control-id",
        primaryControlId,
        "--link-control-id",
        secondaryControlId,
        "--note",
        "Synthetic control evidence",
        "--write",
        "--confirm",
        "control-evidence.csv",
        "--json",
      ],
      fixtureEnv(server.url, tempDir),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.equal(payload.data.evidence.fileName, "control-evidence.csv");
    assert.equal(payload.data.evidence.controlCount, 2);
    assert.deepEqual(payload.data.evidence.controlIds.sort(), [primaryControlId, secondaryControlId].sort());
    assert.deepEqual(
      payload.data.actions.map((action) => action.action),
      ["uploaded", "linked-during-upload", "linked-control"],
    );
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `POST /api/v1/tenants/${tenantId}/evidence`,
      `POST /api/v1/evidence/${evidenceId}/link`,
      `GET /api/v1/evidence/${evidenceId}`,
    ]);
    assert.equal(server.uploadBody.includes("control-evidence.csv"), true);
    assert.equal(server.uploadBody.includes("Synthetic control evidence"), true);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("evidence link-control writes an existing evidence association", async () => {
  const server = await startEvidenceServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-evidence-link-"));

  try {
    const result = await runCli(
      [
        "evidence",
        "link-control",
        evidenceId,
        "--control-id",
        secondaryControlId,
        "--write",
        "--confirm",
        evidenceId,
        "--json",
      ],
      fixtureEnv(server.url, tempDir),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.deepEqual(payload.data.evidence.controlIds, [primaryControlId, secondaryControlId]);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `POST /api/v1/evidence/${evidenceId}/link`,
      `GET /api/v1/evidence/${evidenceId}`,
    ]);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

async function startEvidenceServer() {
  const requests = [];
  let uploadBody = "";
  let controlIds = [primaryControlId];

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });
    if (request.method === "POST" && url.pathname === `/api/v1/tenants/${tenantId}/evidence`) {
      assert.match(request.headers["content-type"] || "", /^multipart\/form-data/);
      uploadBody = await readRequestBody(request);
      controlIds = [primaryControlId];
      writeJson(response, {
        data: {
          id: evidenceId,
          type: "FILE",
          fileName: "control-evidence.csv",
          controlIds,
          vendorIds: [],
        },
      });
      return;
    }

    if (request.method === "POST" && url.pathname === `/api/v1/evidence/${evidenceId}/link`) {
      const body = JSON.parse(await readRequestBody(request));
      assert.equal(body.controlId, secondaryControlId);
      controlIds = Array.from(new Set([...controlIds, body.controlId]));
      writeJson(response, { ok: true });
      return;
    }

    if (request.method === "GET" && url.pathname === `/api/v1/evidence/${evidenceId}`) {
      writeJson(response, {
        data: {
          id: evidenceId,
          type: "FILE",
          fileName: "control-evidence.csv",
          controlIds,
          vendorIds: [],
          updatedAt: "2026-05-28T00:00:00.000Z",
        },
      });
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
    get uploadBody() {
      return uploadBody;
    },
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("error", reject);
    request.on("end", () => resolve(body));
  });
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
