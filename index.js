"use strict";

const { createHmac, randomBytes, randomInt, timingSafeEqual } = require("node:crypto");
const path = require("node:path");
const express = require("express");
const helmet = require("helmet");
const drawCaptcha = require("svg-captcha");
const { createTurnstile, TURNSTILE_ORIGIN } = require("./turnstile");

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 6;
const CHALLENGE_MS = 2 * 60_000;
const WINDOW_MS = 60_000;
const MAX_ATTEMPTS = 5;
const MAX_CHALLENGES = 2_000;
const MAX_BUCKETS = 10_000;
const RISK_MS = 5 * WINDOW_MS;
const COOLDOWN_MS = 45_000;
const QUICK_SUBMIT_MS = 750;
const tokenPattern = /^[a-f0-9]{48}$/;
const answerPattern = new RegExp("^[A-Za-z2-9]{" + CODE_LENGTH + "}$");

function randomToken() {
  return randomBytes(24).toString("hex");
}

function randomAnswer() {
  return Array.from({ length: CODE_LENGTH }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
}

function readCookie(req, name) {
  const prefix = name + "=";
  const values = (req.headers.cookie || "").split(";").map((part) => part.trim())
    .filter((part) => part.startsWith(prefix));
  return values.length === 1 ? values[0].slice(prefix.length) : "";
}

function createApp({ origin, now = Date.now, makeAnswer = randomAnswer, turnstile } = {}) {
  const app = express();
  const secure = origin?.startsWith("https://") ?? false;
  const cookieName = secure ? "__Host-ac_session" : "ac_session";
  const secret = randomBytes(32);
  const challenges = new Map();
  const buckets = new Map();
  const risks = new Map();
  let nextSweep = 0;
  let providerRequests = 0;

  app.disable("x-powered-by");
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'", ...(turnstile ? [TURNSTILE_ORIGIN] : [])],
        frameSrc: turnstile ? [TURNSTILE_ORIGIN] : ["'none'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"]
      }
    },
    strictTransportSecurity: secure
  }));
  app.use(express.static(path.join(__dirname, "public"), { index: false }));
  app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

  function sweep(time) {
    if (time < nextSweep) return;
    nextSweep = time + 15_000;
    for (const [key, entry] of challenges) {
      if (entry.until <= time) challenges.delete(key);
    }
    for (const [key, entry] of risks) {
      if (entry.until <= time) risks.delete(key);
    }
    for (const [key, entry] of buckets) {
      if (entry.until <= time) buckets.delete(key);
    }
  }

  function digest(purpose, ...values) {
    return createHmac("sha256", secret).update(JSON.stringify([purpose, ...values])).digest();
  }

  function verifiedSession(req) {
    const [id, signature, extra] = readCookie(req, cookieName).split(".");
    if (!tokenPattern.test(id) || !/^[a-f0-9]{64}$/.test(signature || "") || extra !== undefined) return null;
    return timingSafeEqual(Buffer.from(signature, "hex"), digest("cookie", id)) ? id : null;
  }

  function enforceLimit(res, scope, identity, limit, time) {
    const key = digest("rate", scope, identity).toString("hex");
    const current = buckets.get(key);
    if (current && current.until > time) {
      if (current.count < limit) {
        current.count += 1;
        return true;
      }
      res.set("Retry-After", String(Math.ceil((current.until - time) / 1000)));
      res.status(429).json({ error: "rate_limited" });
      return false;
    }
    if (!current && buckets.size >= MAX_BUCKETS) {
      res.set("Retry-After", "15").status(503).json({ error: "busy" });
      return false;
    }
    buckets.set(key, { count: 1, until: time + WINDOW_MS });
    return true;
  }

  function riskKey(scope, identity) {
    return digest("risk", scope, identity).toString("hex");
  }

  function risk(scope, identity, time) {
    const entry = risks.get(riskKey(scope, identity));
    return entry && entry.until > time ? entry : undefined;
  }

  function countRisk(scope, identity, time, cooldown = false) {
    const key = riskKey(scope, identity);
    let entry = risks.get(key);
    if (!entry && risks.size >= MAX_BUCKETS) return false;
    if (!entry || entry.until <= time) {
      entry = { count: 0, until: time + RISK_MS, cooldownUntil: 0 };
      risks.set(key, entry);
    }
    entry.count += 1;
    if (cooldown) {
      entry.cooldownUntil = time + COOLDOWN_MS;
      entry.until = Math.max(entry.until, entry.cooldownUntil);
    }
    return true;
  }

  function busy(res) {
    return res.set("Retry-After", "15").status(503).json({ error: "busy" });
  }

  function cooldown(res, time, until) {
    return res.set("Retry-After", String(Math.ceil((until - time) / 1000)))
      .status(429).json({ error: "rate_limited" });
  }

  app.use("/api", (req, res, next) => {
    res.set("Cache-Control", "no-store");
    if (req.method !== "POST") {
      return res.set("Allow", "POST").status(405).json({ error: "method_not_allowed" });
    }
    const requestOrigin = origin || "http://" + req.get("host");
    const fetchSite = req.get("sec-fetch-site");
    if (req.get("origin") !== requestOrigin || (fetchSite && fetchSite !== "same-origin")) {
      return res.status(403).json({ error: "origin_rejected" });
    }
    if (!req.is("application/json")) {
      return res.status(415).json({ error: "json_required" });
    }
    res.locals.time = now();
    res.locals.session = verifiedSession(req);
    sweep(res.locals.time);
    next();
  });

  function limitAction(action, ipLimit, sessionLimit) {
    return (req, res, next) => {
      const { session, time } = res.locals;
      if (!enforceLimit(res, action + ":ip", req.ip, ipLimit, time)) return;
      const until = session && risk("session", session, time)?.cooldownUntil;
      if (until > time) return cooldown(res, time, until);
      if (session && !enforceLimit(res, action + ":session", session, sessionLimit, time)) return;
      next();
    };
  }

  const parseJson = express.json({ limit: "4kb", inflate: false });

  function issueChallenge(res, activeSession, time, isAdditional = false) {
    if (challenges.size >= MAX_CHALLENGES) {
      busy(res);
      return null;
    }
    if (!enforceLimit(res, "issue:global", "all", 240, time)) return null;
    const id = randomToken();
    const answer = makeAnswer();
    const svg = drawCaptcha(answer, { width: 260, height: 92, fontSize: 54, color: false, noise: 4 });
    challenges.set(id, {
      owner: digest("session", activeSession),
      expected: digest("answer", id, answer),
      issuedAt: time,
      until: time + CHALLENGE_MS,
      remaining: MAX_ATTEMPTS,
      isAdditional,
      checking: false
    });
    return {
      id,
      image: "data:image/svg+xml;base64," + Buffer.from(svg).toString("base64"),
      expiresIn: CHALLENGE_MS / 1000,
      ...(turnstile && { siteKey: turnstile.siteKey })
    };
  }

  app.post("/api/challenges", limitAction("issue", 24, 8), parseJson, (req, res) => {
    const { session, time } = res.locals;
    const activeSession = session || randomToken();
    if (!session && !enforceLimit(res, "issue:session", activeSession, 8, time)) return;
    if (!countRisk("issuance", activeSession, time)) return busy(res);
    const challenge = issueChallenge(res, activeSession, time);
    if (!challenge) return;
    if (!session) {
      const signature = digest("cookie", activeSession).toString("hex");
      res.cookie(cookieName, activeSession + "." + signature, { httpOnly: true, secure, sameSite: "strict", path: "/" });
    }
    res.status(201).json(challenge);
  });

  app.post("/api/verify", limitAction("submit", 30, 12), parseJson, async (req, res) => {
    const { id, answer, reference = "", providerToken } = req.body || {};
    if (typeof id !== "string" || !tokenPattern.test(id) || typeof answer !== "string" ||
        answer.length > 24) {
      return res.status(400).json({ error: "invalid_input" });
    }
    if (typeof reference !== "string" || reference.length > 256) {
      return res.status(400).json({ error: "invalid_input" });
    }
    const normalized = answer.trim();
    if (!answerPattern.test(normalized)) {
      return res.status(400).json({ error: "invalid_input" });
    }

    const { session, time } = res.locals;
    const challenge = challenges.get(id);
    if (challenge && challenge.until <= time) challenges.delete(id);
    if (!session || !challenge || challenge.until <= time ||
        !timingSafeEqual(challenge.owner, digest("session", session))) {
      return res.status(410).json({ error: "challenge_unavailable", refresh: true });
    }

    if (challenge.checking) return res.status(409).json({ error: "verification_pending" });

    if (reference.trim()) {
      challenges.delete(id);
      if (!countRisk("session", session, time, true)) return busy(res);
      countRisk("network", req.ip, time);
      return cooldown(res, time, time + COOLDOWN_MS);
    }

    if (!timingSafeEqual(challenge.expected, digest("answer", id, normalized.toUpperCase()))) {
      countRisk("session", session, time);
      countRisk("network", req.ip, time);
      challenge.remaining -= 1;
      const refresh = challenge.remaining === 0;
      if (refresh) challenges.delete(id);
      return res.status(422).json({ error: "incorrect_answer", refresh });
    }

    const sessionFailures = risk("session", session, time)?.count || 0;
    const networkFailures = risk("network", req.ip, time)?.count || 0;
    const issued = risk("issuance", session, time)?.count || 0;
    const quickAndRepeated = time - challenge.issuedAt < QUICK_SUBMIT_MS && (issued >= 3 || sessionFailures >= 2);
    if (!challenge.isAdditional && (sessionFailures >= 3 || networkFailures >= 8 || quickAndRepeated)) {
      const next = issueChallenge(res, session, time, true);
      if (next) {
        challenges.delete(id);
        res.status(202).json({ verification: "additional", challenge: next });
      }
      return;
    }

    if (turnstile) {
      if (typeof providerToken !== "string" || !providerToken || providerToken.length > 2048) {
        return res.status(422).json({ error: "provider_required" });
      }
      if (providerRequests >= 32) return busy(res);
      challenge.checking = true;
      providerRequests += 1;
      try {
        if (!await turnstile.verify(providerToken, id)) {
          return res.status(422).json({ error: "provider_rejected" });
        }
      } catch {
        return busy(res);
      } finally {
        providerRequests -= 1;
        challenge.checking = false;
      }
      if (challenge.until <= now() || challenges.get(id) !== challenge) {
        challenges.delete(id);
        return res.status(410).json({ error: "challenge_unavailable", refresh: true });
      }
    }

    challenges.delete(id);
    res.json({ accepted: true });
  });

  app.use("/api", (req, res) => res.status(404).json({ error: "not_found" }));
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const status = [400, 413, 415].includes(err.status) ? err.status : 500;
    return res.status(status).json({ error: status === 500 ? "server_error" : "invalid_body" });
  });
  return app;
}

if (require.main === module) {
  const origin = process.env.APP_ORIGIN;
  if (origin && new URL(origin).origin !== origin) {
    throw new Error("APP_ORIGIN must be a canonical origin without a trailing slash");
  }
  if (process.env.NODE_ENV === "production" && !origin?.startsWith("https://")) {
    throw new Error("Production requires an HTTPS APP_ORIGIN");
  }
  const host = process.env.HOST || "127.0.0.1";
  const port = Number(process.env.PORT || 3000);
  const turnstile = createTurnstile({
    origin,
    siteKey: process.env.TURNSTILE_SITE_KEY,
    secret: process.env.TURNSTILE_SECRET_KEY
  });
  createApp({ origin, turnstile }).listen(port, host, () => {
    console.log("Advanced Captcha demo listening on " + host + ":" + port);
  });
}

module.exports = { createApp };
