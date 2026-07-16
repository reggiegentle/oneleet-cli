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
const eligibleMemberId = "00000000-0000-4000-8000-000000000101";
const recentMemberId = "00000000-0000-4000-8000-000000000102";
const compliantMemberId = "00000000-0000-4000-8000-000000000103";
const eligibleUserId = "00000000-0000-4000-8000-000000000201";
const recentUserId = "00000000-0000-4000-8000-000000000202";
const compliantUserId = "00000000-0000-4000-8000-000000000203";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("training reminders are dry-run by default and exclude recently reminded members", async () => {
  const server = await startTrainingServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-training-reminder-dry-run-"));

  try {
    const result = await runCli(["security-training", "remind-noncompliant", "--json"], fixtureEnv(server.url, tempConfigHome));
    assert.equal(result.code, 0, result.stderr || result.stdout);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, true);
    assert.equal(payload.data.summary.progressCount, 3);
    assert.equal(payload.data.summary.noncompliantCount, 2);
    assert.equal(payload.data.summary.targetCount, 1);
    assert.equal(payload.data.summary.recentlyRemindedCount, 1);
    assert.deepEqual(payload.data.targets, [
      {
        ref: "training-reminder-001",
        hasId: true,
        hadPreviousReminder: false,
        portalTasks: ["SECURITY_TRAINING"],
      },
    ]);
    assert.equal(server.reminderBodies.length, 0);
    assert.equal(result.stdout.includes(eligibleMemberId), false);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

test("training reminders write the typed bulk-reminder payload and read back cooldown state", async () => {
  const server = await startTrainingServer();
  const tempConfigHome = await mkdtemp(path.join(os.tmpdir(), "oneleet-cli-training-reminder-write-"));

  try {
    const result = await runCli(
      ["security-training", "remind-noncompliant", "--write", "--confirm", "security-training", "--json"],
      fixtureEnv(server.url, tempConfigHome),
    );
    assert.equal(result.code, 0, result.stderr || result.stdout);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.ok, true);
    assert.equal(payload.data.dryRun, false);
    assert.equal(payload.data.writtenCount, 1);
    assert.equal(payload.data.after.summary.targetCount, 0);
    assert.equal(payload.data.after.summary.recentlyRemindedCount, 2);
    assert.deepEqual(server.reminderBodies, [
      {
        reminders: [{ memberId: eligibleMemberId, portalTasks: ["SECURITY_TRAINING"] }],
      },
    ]);
    assert.deepEqual(server.requests.map((request) => `${request.method} ${request.pathname}`), [
      `GET /api/v1/tenants/${tenantId}/members`,
      `GET /api/v1/tenants/${tenantId}/security-training-modules/user-progress`,
      `POST /api/v1/tenants/${tenantId}/remind-members/tasks`,
      `GET /api/v1/tenants/${tenantId}/members`,
      `GET /api/v1/tenants/${tenantId}/security-training-modules/user-progress`,
    ]);
    assert.equal(result.stdout.includes(eligibleMemberId), false);
    assert.equal(result.stdout.includes(fakeCookie), false);
  } finally {
    await server.close();
    await rm(tempConfigHome, { recursive: true, force: true });
  }
});

async function startTrainingServer() {
  const requests = [];
  const reminderBodies = [];
  let eligibleReminderSent = false;

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    requests.push({ method: request.method, pathname: url.pathname });

    if (request.method === "GET" && url.pathname === `/api/v1/tenants/${tenantId}/members`) {
      writeJson(response, { rows: memberFixtures(eligibleReminderSent) });
      return;
    }
    if (request.method === "GET" && url.pathname === `/api/v1/tenants/${tenantId}/security-training-modules/user-progress`) {
      writeJson(response, progressFixtures());
      return;
    }
    if (request.method === "POST" && url.pathname === `/api/v1/tenants/${tenantId}/remind-members/tasks`) {
      const body = JSON.parse(await readRequestBody(request));
      reminderBodies.push(body);
      eligibleReminderSent = true;
      writeJson(response, { ok: true });
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
    reminderBodies,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function memberFixtures(eligibleReminderSent) {
  const now = new Date().toISOString();
  return [
    memberFixture(eligibleMemberId, eligibleUserId, eligibleReminderSent ? now : undefined),
    memberFixture(recentMemberId, recentUserId, now),
    memberFixture(compliantMemberId, compliantUserId, undefined),
  ];
}

function memberFixture(id, userId, lastTasksReminderSentAt) {
  return {
    id,
    name: "Synthetic Member",
    status: "CURRENT",
    enableNotifications: true,
    lastTasksReminderSentAt,
    user: { id: userId, email: "synthetic@example.invalid" },
  };
}

function progressFixtures() {
  return [
    { id: eligibleUserId, fullName: "Eligible Synthetic", email: "eligible@example.invalid", isCompliant: false },
    { id: recentUserId, fullName: "Recent Synthetic", email: "recent@example.invalid", isCompliant: false },
    { id: compliantUserId, fullName: "Compliant Synthetic", email: "compliant@example.invalid", isCompliant: true },
  ];
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
