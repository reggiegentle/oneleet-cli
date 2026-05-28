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
const riskId = "00000000-0000-4000-8000-000000000301";
const auditControlId = "00000000-0000-4000-8000-000000000401";
const oldControlId = "00000000-0000-4000-8000-000000000402";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("risk controls is dry-run by default and resolves exact control titles", async () => {
  const server = await startRiskServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-risk-controls-dry-run-"));

  try {
    const result = await runCli(
      [
        "risks",
        "controls",
        riskId,
        "--control-title",
        "Audit logs collected",
        "--unlink-control-title",
        "Old Control",
        "--json",
      ],
      fixtureEnv(server.url, tempDir),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, true);
    assert.deepEqual(payload.data.patch.controls, [
      { controlId: auditControlId, link: true },
      { controlId: oldControlId, link: false },
    ]);
    assert.deepEqual(
      payload.data.resolvedControls.map((control) => ({ title: control.title, link: control.link })),
      [
        { title: "Audit logs collected", link: true },
        { title: "Old Control", link: false },
      ],
    );
    assert.equal(payload.data.before.controls[0].title, "Old Control");
    assert.equal(server.patchBodies.length, 0);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/risks/${riskId}`,
      `GET /api/v1/tenants/${tenantId}/controls/program`,
    ]);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("risk controls writes link and unlink actions", async () => {
  const server = await startRiskServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-risk-controls-write-"));

  try {
    const result = await runCli(
      [
        "risks",
        "controls",
        riskId,
        "--control-id",
        auditControlId,
        "--unlink-control-title",
        "Old Control",
        "--write",
        "--confirm",
        riskId,
        "--json",
      ],
      fixtureEnv(server.url, tempDir),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.deepEqual(server.patchBodies, [{ controls: [{ controlId: auditControlId, link: true }, { controlId: oldControlId, link: false }] }]);
    assert.deepEqual(payload.data.after.controls.map((control) => control.id), [auditControlId]);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/risks/${riskId}`,
      `GET /api/v1/tenants/${tenantId}/controls/program`,
      `PATCH /api/v1/risks/${riskId}`,
      `GET /api/v1/risks/${riskId}`,
    ]);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("risk archive writes through the guarded archive endpoint", async () => {
  const server = await startRiskServer();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-risk-archive-write-"));

  try {
    const result = await runCli(["risks", "archive", riskId, "--write", "--confirm", riskId, "--json"], fixtureEnv(server.url, tempDir));

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.equal(payload.data.action, "archive");
    assert.equal(payload.data.result.archived, true);
    assert.equal(server.archived, true);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `GET /api/v1/risks/${riskId}`,
      `POST /api/v1/risks/${riskId}/archive`,
      `GET /api/v1/risks/${riskId}`,
    ]);
  } finally {
    await server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

async function startRiskServer() {
  const requests = [];
  const patchBodies = [];
  let archived = false;
  let controlIds = [oldControlId];

  const controls = [
    { id: auditControlId, title: "Audit logs collected", status: "NOT_STARTED" },
    { id: oldControlId, title: "Old Control", status: "IN_PROGRESS" },
  ];

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });

    if (request.method === "GET" && url.pathname === `/api/v1/risks/${riskId}`) {
      writeJson(response, { data: riskRow() });
      return;
    }

    if (request.method === "GET" && url.pathname === `/api/v1/tenants/${tenantId}/controls/program`) {
      writeJson(response, { data: controls });
      return;
    }

    if (request.method === "PATCH" && url.pathname === `/api/v1/risks/${riskId}`) {
      const body = JSON.parse(await readRequestBody(request));
      patchBodies.push(body);
      for (const action of body.controls || []) {
        if (action.link) controlIds = Array.from(new Set([...controlIds, action.controlId]));
        else controlIds = controlIds.filter((id) => id !== action.controlId);
      }
      writeJson(response, { data: riskRow() });
      return;
    }

    if (request.method === "POST" && url.pathname === `/api/v1/risks/${riskId}/archive`) {
      archived = true;
      writeJson(response, { data: { id: riskId, archived } });
      return;
    }

    if (request.method === "POST" && url.pathname === `/api/v1/risks/${riskId}/unarchive`) {
      archived = false;
      writeJson(response, { data: { id: riskId, archived } });
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
    patchBodies,
    get archived() {
      return archived;
    },
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };

  function riskRow() {
    return {
      id: riskId,
      title: "Synthetic HIPAA risk",
      description: "Synthetic description",
      response: "MITIGATE",
      controls: controlIds.map((id) => {
        const control = controls.find((candidate) => candidate.id === id);
        return { id, status: control?.status || "NOT_STARTED", controlType: { title: control?.title || "Unknown Control" } };
      }),
      archived,
      updatedAt: "2026-05-28T00:00:00.000Z",
    };
  }
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
