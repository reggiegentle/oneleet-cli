import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import ws from "ws";

import { importFromCdp } from "../dist/auth.js";

const { Server: WebSocketServer } = ws;
const tenantId = "00000000-0000-4000-8000-000000000001";
const fakeCookie = "synthetic-cookie-do-not-leak";

test("auth import reads a Oneleet cookie from a synthetic CDP target", async () => {
  const cdp = await startCdpFixture();

  try {
    const config = await importFromCdp({ host: "127.0.0.1", port: cdp.port });

    assert.equal(config.tenantId, tenantId);
    assert.equal(config.oneleetAppCookie, fakeCookie);
    assert.equal(config.appBaseUrl, "https://app.oneleet.com");
    assert.equal(config.apiBaseUrl, "https://api.oneleet.com");
    assert.deepEqual(cdp.methodsSeen, ["Network.enable", "Runtime.enable", "Runtime.evaluate", "Network.getCookies"]);
  } finally {
    await cdp.close();
  }
});

async function startCdpFixture() {
  const methodsSeen = [];
  const server = http.createServer((request, response) => {
    if (request.url === "/json/protocol") {
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          domains: [
            { domain: "Network", commands: [{ name: "enable" }, { name: "getCookies" }] },
            { domain: "Runtime", commands: [{ name: "enable" }, { name: "evaluate" }] },
          ],
        }),
      );
      return;
    }

    if (request.url === "/json/list") {
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify([
          {
            id: "synthetic-oneleet-page",
            type: "page",
            url: `https://app.oneleet.com/tenants/${tenantId}/dashboard`,
            webSocketDebuggerUrl: `ws://127.0.0.1:${server.address().port}/devtools/page/synthetic-oneleet-page`,
          },
        ]),
      );
      return;
    }

    response.statusCode = 404;
    response.end("not found");
  });
  const wss = new WebSocketServer({ server });

  wss.on("connection", (socket) => {
    socket.on("message", (raw) => {
      const message = JSON.parse(String(raw));
      methodsSeen.push(message.method);

      if (message.method === "Runtime.evaluate") {
        socket.send(
          JSON.stringify({
            id: message.id,
            result: {
              result: {
                type: "string",
                value: JSON.stringify({ href: `https://app.oneleet.com/tenants/${tenantId}/dashboard`, title: "Oneleet" }),
              },
            },
          }),
        );
        return;
      }

      if (message.method === "Network.getCookies") {
        socket.send(
          JSON.stringify({
            id: message.id,
            result: {
              cookies: [{ name: "oneleet-app", value: fakeCookie }],
            },
          }),
        );
        return;
      }

      socket.send(JSON.stringify({ id: message.id, result: {} }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    port: server.address().port,
    methodsSeen,
    close: async () => {
      await new Promise((resolve) => wss.close(resolve));
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
