"use strict";

const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
const ACTION = "verify";

function createTurnstile({ origin, siteKey, secret, request = fetch }) {
  if (!siteKey && !secret) return undefined;
  if (!origin || !siteKey || !secret) {
    throw new Error("Turnstile requires APP_ORIGIN, TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY");
  }
  const hostname = new URL(origin).hostname;
  return {
    siteKey,
    async verify(token, challengeId) {
      const response = await request(TURNSTILE_ORIGIN + "/turnstile/v0/siteverify", {
        method: "POST",
        body: new URLSearchParams({ secret, response: token }),
        signal: AbortSignal.timeout(3000),
        redirect: "error"
      });
      if (!response.ok) throw new Error("Turnstile is unavailable");
      const result = await response.json();
      if (result["error-codes"]?.some((code) => ["internal-error", "invalid-input-secret", "missing-input-secret"].includes(code))) {
        throw new Error("Turnstile configuration or service error");
      }
      return result.success === true && result.hostname === hostname &&
        result.action === ACTION && result.cdata === challengeId;
    }
  };
}

module.exports = { createTurnstile, TURNSTILE_ORIGIN };
