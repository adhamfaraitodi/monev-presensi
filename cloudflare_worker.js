/**
 * HARDENED CLOUDFLARE WORKER REVERSE PROXY & CRON FOR KEMNAKER MONEV
 *
 * Security & Controls:
 * - Fail-closed (503) if PROXY_SECRET is not configured in Worker env.
 * - Constant-time verification of X-Proxy-Secret header (403 on mismatch).
 * - Strict allowlist restricted to kemnaker.go.id and *.kemnaker.go.id
 *   for both target URL and upstream Location redirects, automatically upgrading
 *   any internal http://*.kemnaker.go.id redirect to https:// before fetching.
 * - Strips X-Proxy-Secret, Host, and cf-* headers upstream.
 * - Preserves multiple Set-Cookie headers cleanly via getSetCookie().
 * - No wildcard CORS headers.
 * - Scheduled 17:00 WIB (10:00 UTC) Mon-Fri cron sends POST /api/cron with
 *   Authorization: Bearer <CRON_SECRET> (never in query string).
 */

const ALLOWED_BASE_DOMAIN = "kemnaker.go.id";

const ALLOWED_HOSTS = new Set([
  "maganghub.kemnaker.go.id",
  "account.kemnaker.go.id",
  "monev-api.maganghub.kemnaker.go.id",
]);

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  const len = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;
  for (let i = 0; i < len; i++) {
    diff |= (aBytes[i] || 0) ^ (bBytes[i] || 0);
  }
  return diff === 0 && aBytes.length > 0;
}

function isAllowedKemnakerHost(hostname) {
  if (typeof hostname !== "string" || !hostname) {
    return false;
  }
  const host = hostname.toLowerCase();
  return (
    host === ALLOWED_BASE_DOMAIN ||
    host.endsWith(`.${ALLOWED_BASE_DOMAIN}`) ||
    ALLOWED_HOSTS.has(host)
  );
}

function normalizeKemnakerUrl(urlObj) {
  if (!(urlObj instanceof URL)) {
    return null;
  }
  if (urlObj.protocol !== "https:" && urlObj.protocol !== "http:") {
    return null;
  }
  if (!isAllowedKemnakerHost(urlObj.hostname)) {
    return null;
  }
  const normalized = new URL(urlObj.toString());
  if (normalized.protocol === "http:") {
    normalized.protocol = "https:";
  }
  return normalized;
}

function isAllowedKemnakerUrl(urlObj) {
  return (
    urlObj instanceof URL &&
    urlObj.protocol === "https:" &&
    isAllowedKemnakerHost(urlObj.hostname)
  );
}

function jsonResponse(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export default {
  async fetch(request, env, _ctx) {
    const expectedSecret =
      env && typeof env.PROXY_SECRET === "string" ? env.PROXY_SECRET.trim() : "";
    if (!expectedSecret) {
      return jsonResponse(503, { error: "PROXY_SECRET is not configured on Worker." });
    }

    const providedSecret = request.headers.get("X-Proxy-Secret") || "";
    if (!timingSafeEqual(providedSecret, expectedSecret)) {
      return jsonResponse(403, { error: "Forbidden: invalid proxy secret." });
    }

    const currentUrl = new URL(request.url);
    const targetUrlStr = currentUrl.searchParams.get("url");
    if (!targetUrlStr) {
      return jsonResponse(400, { error: "Missing target url parameter." });
    }

    let rawTargetUrl;
    try {
      rawTargetUrl = new URL(targetUrlStr);
    } catch (_e) {
      return jsonResponse(400, { error: "Invalid target URL." });
    }

    const targetUrl = normalizeKemnakerUrl(rawTargetUrl);
    if (!targetUrl) {
      return jsonResponse(403, {
        error: `Forbidden target host or protocol (${rawTargetUrl.protocol}//${rawTargetUrl.hostname}).`,
      });
    }

    const newHeaders = new Headers();
    for (const [key, value] of request.headers.entries()) {
      const lower = key.toLowerCase();
      if (
        lower === "host" ||
        lower === "x-proxy-secret" ||
        lower.startsWith("cf-")
      ) {
        continue;
      }
      newHeaders.set(key, value);
    }
    newHeaders.set("Host", targetUrl.host);

    // Strip acw_tc cookie for non-maganghub hosts to avoid WAF timeouts
    if (newHeaders.has("cookie") && targetUrl.hostname !== "maganghub.kemnaker.go.id") {
      const cookieHeader = newHeaders.get("cookie") || "";
      const cleaned = cookieHeader
        .split(";")
        .map((c) => c.trim())
        .filter((c) => c && !c.toLowerCase().startsWith("acw_tc="))
        .join("; ");
      if (cleaned) {
        newHeaders.set("cookie", cleaned);
      } else {
        newHeaders.delete("cookie");
      }
    }

    try {
      const response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: newHeaders,
        body: ["GET", "HEAD"].includes(request.method.toUpperCase())
          ? undefined
          : await request.arrayBuffer(),
        redirect: "manual",
      });

      const responseHeaders = new Headers();
      const setCookies =
        typeof response.headers.getSetCookie === "function"
          ? response.headers.getSetCookie()
          : null;

      if (setCookies && setCookies.length > 0) {
        for (const cookieVal of setCookies) {
          const cleanedCookie = cookieVal.replace(/;\s*domain=[^;]+/gi, "");
          responseHeaders.append("Set-Cookie", cleanedCookie);
        }
      }

      for (const [key, value] of response.headers.entries()) {
        const lower = key.toLowerCase();
        if (lower === "set-cookie") {
          if (!setCookies || setCookies.length === 0) {
            const cleanedCookie = value.replace(/;\s*domain=[^;]+/gi, "");
            responseHeaders.append("Set-Cookie", cleanedCookie);
          }
        } else if (lower === "location") {
          let rawRedirect;
          try {
            rawRedirect = new URL(value, targetUrl);
          } catch (_e) {
            return jsonResponse(403, { error: "Invalid redirect Location from upstream." });
          }
          const resolvedRedirect = normalizeKemnakerUrl(rawRedirect);
          if (!resolvedRedirect) {
            return jsonResponse(403, {
              error: `Forbidden redirect host or protocol (${rawRedirect.protocol}//${rawRedirect.hostname}).`,
            });
          }
          const wrappedRedirect = `${currentUrl.origin}/?url=${encodeURIComponent(
            resolvedRedirect.toString()
          )}`;
          responseHeaders.set("Location", wrappedRedirect);
        } else if (!lower.startsWith("access-control-")) {
          responseHeaders.set(key, value);
        }
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return jsonResponse(502, {
        error: "Failed to connect to Kemnaker upstream.",
        detail: err && err.message ? err.message : String(err),
      });
    }
  },

  /**
   * CRON TRIGGER SCHEDULER: 17:00 WIB (10:00 UTC), Monday-Friday (`0 10 * * 1-5`)
   */
  async scheduled(event, env, ctx) {
    const baseTime =
      event && typeof event.scheduledTime === "number"
        ? event.scheduledTime
        : Date.now();
    const wibDate = new Date(baseTime + 7 * 60 * 60 * 1000);
    const dayOfWeek = wibDate.getUTCDay(); // 0 = Sunday, 6 = Saturday
    if (dayOfWeek === 0 || dayOfWeek === 6) {
      return;
    }

    const vercelDomain =
      env && typeof env.VERCEL_DOMAIN === "string"
        ? env.VERCEL_DOMAIN.trim().replace(/\/+$/, "")
        : "";
    const cronSecret =
      env && typeof env.CRON_SECRET === "string" ? env.CRON_SECRET.trim() : "";
    if (!vercelDomain || !cronSecret) {
      return;
    }

    const targetEndpoint = `${vercelDomain}/api/cron`;
    const reqHeaders = {
      "User-Agent": "Cloudflare-Worker-Cron/2.0",
      Authorization: `Bearer ${cronSecret}`,
      Accept: "application/json",
    };

    const executeScheduledTask = async () => {
      const maxAttempts = 2; // 1 initial + 1 retry on network/5xx
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort("Request Timeout 55s"), 55000);
        try {
          const res = await fetch(targetEndpoint, {
            method: "POST",
            headers: reqHeaders,
            signal: controller.signal,
          });
          clearTimeout(timer);
          await res.text();
          if (res.status < 500) {
            return;
          }
        } catch (_err) {
          clearTimeout(timer);
        }
      }
    };

    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(executeScheduledTask());
    } else {
      await executeScheduledTask();
    }
  },
};

export { ALLOWED_HOSTS, isAllowedKemnakerUrl, normalizeKemnakerUrl, timingSafeEqual };
