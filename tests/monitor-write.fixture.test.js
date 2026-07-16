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
const monitorId = "00000000-0000-4000-8000-000000000301";
const controlId = "00000000-0000-4000-8000-000000000401";
const checkId = "00000000-0000-4000-8000-000000000501";
const assetId = "00000000-0000-4000-8000-000000000601";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("monitor writes are dry-run by default", async () => {
  const result = await runCli(["monitors", "set-enabled", monitorId, "--enabled", "false", "--json"], { PATH: process.env.PATH || "" });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, "");
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.ok, true);
  assert.equal(payload.data.dryRun, true);
  assert.equal(payload.data.monitorId, monitorId);
  assert.deepEqual(payload.data.patch, { enabled: false });
  assert.match(payload.data.writeRequired, new RegExp(`--write --confirm ${monitorId}`));
});

test("monitor set-enabled writes through the Oneleet monitor endpoint", async () => {
  const server = await startMonitorServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-monitor-enabled-"));

  try {
    const result = await runCli(
      [
        "monitors",
        "set-enabled",
        monitorId,
        "--enabled",
        "false",
        "--disabled-reason",
        "Out of scope",
        "--write",
        "--confirm",
        monitorId,
        "--json",
      ],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.equal(payload.data.monitor.status, "DISABLED");
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `POST /api/v1/monitors/${monitorId}/enabled`,
      `GET /api/v1/monitors/${monitorId}`,
    ]);
    assert.deepEqual(server.requestBodies[0], { enabled: false, disabledReason: "Out of scope" });
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("monitor asset ignore writes the Oneleet asset ignore payload", async () => {
  const server = await startMonitorServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-monitor-asset-ignore-"));

  try {
    const result = await runCli(
      [
        "monitors",
        "update-assets-ignore-status",
        monitorId,
        "--ignore-asset-id",
        assetId,
        "--reason",
        "Documented exception",
        "--write",
        "--confirm",
        monitorId,
        "--json",
      ],
      fixtureEnv(server.url, tempConfigHome),
    );

    assert.equal(result.code, 0, result.stderr || result.stdout);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.deepEqual(server.requests.map((request) => request.method + " " + request.pathname), [
      `POST /api/v1/monitors/${monitorId}/update-assets-ignore-status`,
      `GET /api/v1/monitors/${monitorId}`,
    ]);
    assert.deepEqual(server.requestBodies[0], {
      assetsToIgnore: [assetId],
      assetsToUnignore: [],
      reasonToIgnore: "Documented exception",
    });
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("monitor-control and control-check reads summarize linked relationships", async () => {
  const server = await startMonitorServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-monitor-reads-"));

  try {
    const monitorControls = await runCli(["monitors", "controls", monitorId, "--show-ids", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(monitorControls.code, 0, monitorControls.stderr);
    const monitorControlsPayload = JSON.parse(monitorControls.stdout);
    assert.equal(monitorControlsPayload.ok, true);
    assert.equal(monitorControlsPayload.data.rows[0].id, controlId);
    assert.equal(monitorControlsPayload.data.rows[0].title, "Security awareness training conducted");

    const controlChecks = await runCli(["controls", "checks", controlId, "--show-ids", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(controlChecks.code, 0, controlChecks.stderr);
    const controlChecksPayload = JSON.parse(controlChecks.stdout);
    assert.equal(controlChecksPayload.ok, true);
    assert.equal(controlChecksPayload.data.rows[0].id, checkId);
    assert.equal(controlChecksPayload.data.rows[0].monitorId, monitorId);
    assert.equal(controlChecksPayload.data.rows[0].monitorType, "All people have completed applicable security trainings in the past 12 months");
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("monitor detail and relationship reads accept sanitized local refs", async () => {
  const server = await startMonitorServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-monitor-local-refs-"));

  try {
    const monitorDetail = await runCli(["monitors", "get", "monitor-001", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(monitorDetail.code, 0, monitorDetail.stderr);
    const monitorPayload = JSON.parse(monitorDetail.stdout);
    assert.equal(monitorPayload.ok, true);
    assert.equal(monitorPayload.data.monitorType, "All people have completed applicable security trainings in the past 12 months");

    const monitorControls = await runCli(
      ["monitors", "controls", "monitor-001", "--show-ids", "--json"],
      fixtureEnv(server.url, tempConfigHome),
    );
    assert.equal(monitorControls.code, 0, monitorControls.stderr);
    const controlsPayload = JSON.parse(monitorControls.stdout);
    assert.equal(controlsPayload.ok, true);
    assert.equal(controlsPayload.data.rows[0].id, controlId);

    const controlChecks = await runCli(
      ["controls", "checks", "control-001", "--show-ids", "--json"],
      fixtureEnv(server.url, tempConfigHome),
    );
    assert.equal(controlChecks.code, 0, controlChecks.stderr);
    const checksPayload = JSON.parse(controlChecks.stdout);
    assert.equal(checksPayload.ok, true);
    assert.equal(checksPayload.data.rows[0].monitorId, monitorId);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

async function startMonitorServer() {
  const requests = [];
  const requestBodies = [];
  let monitorStatus = "ALERTING";

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });

    if (request.method === "GET" && url.pathname === `/api/v1/tenants/${tenantId}/monitors`) {
      writeJson(response, { rows: [monitorFixture(monitorStatus)] });
      return;
    }

    if (request.method === "GET" && url.pathname === `/api/v1/tenants/${tenantId}/controls/program`) {
      writeJson(response, { rows: [controlFixture()] });
      return;
    }

    if (request.method === "POST" && url.pathname === `/api/v1/monitors/${monitorId}/enabled`) {
      const body = JSON.parse(await readRequestBody(request));
      requestBodies.push(body);
      monitorStatus = body.enabled ? "OK" : "DISABLED";
      writeJson(response, { ok: true });
      return;
    }

    if (request.method === "POST" && url.pathname === `/api/v1/monitors/${monitorId}/update-assets-ignore-status`) {
      requestBodies.push(JSON.parse(await readRequestBody(request)));
      writeJson(response, { ok: true });
      return;
    }

    if (request.method === "GET" && url.pathname === `/api/v1/monitors/${monitorId}`) {
      writeJson(response, monitorFixture(monitorStatus));
      return;
    }

    if (request.method === "GET" && url.pathname === `/api/v1/monitors/${monitorId}/controls`) {
      writeJson(response, {
        rows: [
          {
            id: controlId,
            title: "Security awareness training conducted",
            category: "SECURITY_TRAINING",
            status: "FAILING",
            reviewStatus: "NEEDS_REVIEW",
            tenantComplianceRequirements: [{ referenceId: "164.308(a)(5)(i)" }],
          },
        ],
      });
      return;
    }

    if (request.method === "GET" && url.pathname === `/api/v1/controls/${controlId}/checks`) {
      writeJson(response, {
        rows: [
          {
            id: checkId,
            type: "MONITOR",
            status: "FAILING",
            monitor: monitorFixture("ALERTING"),
          },
        ],
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
    requestBodies,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function monitorFixture(status) {
  return {
    id: monitorId,
    status,
    isEnabled: status !== "DISABLED",
    monitorType: { name: "All people have completed applicable security trainings in the past 12 months" },
    controlSummaries: [{ title: "Security awareness training conducted" }],
    stats: { assets: { count: 10, failingCount: 2, passingCount: 8, percentPassing: 80 } },
    latestRun: { status: "COMPLETE", createdAt: "2026-06-08T15:00:00.000Z" },
    currentState: { status: "OPEN" },
    updatedAt: "2026-06-08T15:00:00.000Z",
  };
}

function controlFixture() {
  return {
    id: controlId,
    status: "FAILING",
    controlType: {
      title: "Security awareness training conducted",
      category: "SECURITY_TRAINING",
    },
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
