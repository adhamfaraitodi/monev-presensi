import test from "node:test";
import assert from "node:assert/strict";
import worker from "../cloudflare_worker.js";

const ENV = {
  PROXY_SECRET: "super_secret_proxy_key_123456",
  CRON_SECRET: "super_secret_cron_key_123456",
  VERCEL_DOMAIN: "https://monev.example.vercel.app",
};

test("fails closed with 503 when PROXY_SECRET env is missing", async () => {
  const req = new Request("https://w.workers.dev/?url=https://maganghub.kemnaker.go.id/");
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 503);
});

test("rejects missing or wrong X-Proxy-Secret with 403", async () => {
  const req = new Request("https://w.workers.dev/?url=https://maganghub.kemnaker.go.id/", {
    headers: { "X-Proxy-Secret": "wrong" },
  });
  const res = await worker.fetch(req, ENV, {});
  assert.equal(res.status, 403);
});

test("rejects non-kemnaker hosts, lookalike domains, and non-http(s) protocols with 403", async () => {
  for (const bad of [
    "https://evil.example.com/",
    "https://evil-kemnaker.go.id/",
    "https://kemnaker.go.id.evil.com/",
    "ftp://maganghub.kemnaker.go.id/",
  ]) {
    const req = new Request(`https://w.workers.dev/?url=${encodeURIComponent(bad)}`, {
      headers: { "X-Proxy-Secret": ENV.PROXY_SECRET },
    });
    const res = await worker.fetch(req, ENV, {});
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.match(body.error, /Forbidden target host or protocol \(/);
  }
});

test("auto-upgrades http://*.kemnaker.go.id target URL and http:// Location redirects to https://", async () => {
  const origFetch = globalThis.fetch;
  const fetchedUrls = [];
  globalThis.fetch = async (url, _opts) => {
    fetchedUrls.push(url);
    return new Response(null, {
      status: 302,
      headers: {
        Location: "http://account.kemnaker.go.id/auth/login",
      },
    });
  };
  try {
    const req = new Request(
      `https://w.workers.dev/?url=${encodeURIComponent("http://account.kemnaker.go.id/auth")}`,
      { headers: { "X-Proxy-Secret": ENV.PROXY_SECRET } }
    );
    const res = await worker.fetch(req, ENV, {});
    assert.equal(res.status, 302);
    assert.equal(fetchedUrls[0], "https://account.kemnaker.go.id/auth");
    assert.equal(
      res.headers.get("Location"),
      `https://w.workers.dev/?url=${encodeURIComponent("https://account.kemnaker.go.id/auth/login")}`
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("allows legitimate kemnaker.go.id subdomains (e.g. siapkerja.kemnaker.go.id) and preserves multiple Set-Cookie headers", async () => {
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    const h = new Headers();
    h.append("Set-Cookie", "acw_tc=abc; Domain=.kemnaker.go.id; Path=/");
    h.append("Set-Cookie", "kemnaker_ri_session=sess123; Domain=.kemnaker.go.id; Path=/; HttpOnly");
    return new Response("ok", { status: 200, headers: h });
  };
  try {
    const req = new Request(
      `https://w.workers.dev/?url=${encodeURIComponent("https://siapkerja.kemnaker.go.id/auth/callback")}`,
      { headers: { "X-Proxy-Secret": ENV.PROXY_SECRET } }
    );
    const res = await worker.fetch(req, ENV, {});
    assert.equal(res.status, 200);
    const cookies = res.headers.getSetCookie();
    assert.equal(cookies.length, 2);
    assert.equal(cookies[0], "acw_tc=abc; Path=/");
    assert.equal(cookies[1], "kemnaker_ri_session=sess123; Path=/; HttpOnly");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("strips X-Proxy-Secret upstream, rejects redirect to non-Kemnaker host, no wildcard CORS", async () => {
  const origFetch = globalThis.fetch;
  let capturedHeaders;
  globalThis.fetch = async (_url, opts) => {
    capturedHeaders = opts.headers;
    return new Response(null, { status: 302, headers: { Location: "https://evil.example/steal" } });
  };
  try {
    const req = new Request(
      `https://w.workers.dev/?url=${encodeURIComponent("https://maganghub.kemnaker.go.id/api/naco/login")}`,
      { headers: { "X-Proxy-Secret": ENV.PROXY_SECRET } }
    );
    const res = await worker.fetch(req, ENV, {});
    assert.equal(capturedHeaders.has("x-proxy-secret"), false);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("access-control-allow-origin"), null);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("wraps valid Kemnaker redirect Location, strips Set-Cookie domain, and filters acw_tc cookie on non-maganghub host", async () => {
  const origFetch = globalThis.fetch;
  let capturedCookie;
  globalThis.fetch = async (_url, opts) => {
    capturedCookie = opts.headers.get("cookie");
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/auth/callback?code=abc",
        "Set-Cookie": "naco_access_token=jwt123; Domain=.kemnaker.go.id; Path=/; HttpOnly",
      },
    });
  };
  try {
    const req = new Request(
      `https://w.workers.dev/?url=${encodeURIComponent("https://account.kemnaker.go.id/auth/login")}`,
      {
        headers: {
          "X-Proxy-Secret": ENV.PROXY_SECRET,
          Cookie: "acw_tc=waf123; session_id=xyz",
        },
      }
    );
    const res = await worker.fetch(req, ENV, {});
    assert.equal(capturedCookie, "session_id=xyz");
    assert.equal(res.status, 302);
    assert.equal(
      res.headers.get("Location"),
      `https://w.workers.dev/?url=${encodeURIComponent("https://account.kemnaker.go.id/auth/callback?code=abc")}`
    );
    assert.equal(
      res.headers.get("Set-Cookie"),
      "naco_access_token=jwt123; Path=/; HttpOnly"
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("scheduled skips weekend and sends POST with Bearer header (not query string) on weekday", async () => {
  const origFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return new Response('{"status":"submitted"}', { status: 200 });
  };
  try {
    const promises = [];
    const ctx = { waitUntil: (p) => promises.push(p) };
    // Sunday 2026-11-22 10:00 UTC (17:00 WIB)
    await worker.scheduled({ cron: "0 10 * * 1-5", scheduledTime: Date.UTC(2026, 10, 22, 10, 0, 0) }, ENV, ctx);
    await Promise.all(promises);
    assert.equal(calls.length, 0);

    // Monday 2026-11-23 10:00 UTC (17:00 WIB)
    await worker.scheduled({ cron: "0 10 * * 1-5", scheduledTime: Date.UTC(2026, 10, 23, 10, 0, 0) }, ENV, ctx);
    await Promise.all(promises);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://monev.example.vercel.app/api/cron");
    assert.equal(calls[0].opts.method, "POST");
    assert.equal(calls[0].opts.headers["Authorization"], `Bearer ${ENV.CRON_SECRET}`);
    assert.equal(calls[0].url.includes("secret="), false);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("scheduled retries once on 5xx error", async () => {
  const origFetch = globalThis.fetch;
  let attempts = 0;
  globalThis.fetch = async () => {
    attempts += 1;
    if (attempts === 1) {
      return new Response('{"error":"upstream timeout"}', { status: 502 });
    }
    return new Response('{"status":"submitted"}', { status: 200 });
  };
  try {
    const promises = [];
    const ctx = { waitUntil: (p) => promises.push(p) };
    await worker.scheduled({ cron: "0 10 * * 1-5", scheduledTime: Date.UTC(2026, 10, 23, 10, 0, 0) }, ENV, ctx);
    await Promise.all(promises);
    assert.equal(attempts, 2);
  } finally {
    globalThis.fetch = origFetch;
  }
});
