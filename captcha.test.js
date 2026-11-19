"use strict";

const assert = require("node:assert/strict");
const { once } = require("node:events");
const { test } = require("node:test");
const { createApp } = require("./index");

const rightAnswer = "ABCD23";
const wrongAnswer = "ZBCD23";

async function fixture(t, options = {}) {
  let time = 10_000;
  const app = createApp({ now: () => time, makeAnswer: () => rightAnswer, ...options });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const url = "http://127.0.0.1:" + server.address().port;

  function post(route, body, { cookie, origin = options.origin || url, headers = {} } = {}) {
    return fetch(url + route, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(origin && { Origin: origin }),
        ...(cookie && { Cookie: cookie }),
        ...headers
      },
      body: typeof body === "string" ? body : JSON.stringify(body)
    });
  }

  async function issue(cookie) {
    const response = await post("/api/challenges", {}, { cookie });
    assert.equal(response.status, 201);
    const session = cookie || response.headers.get("set-cookie").split(";")[0];
    return { response, cookie: session, ...(await response.json()) };
  }

  function submit(challenge, answer = rightAnswer, cookie = challenge.cookie) {
    return post("/api/verify", { id: challenge.id, answer }, { cookie });
  }

  return { url, issue, submit, post, advance: (ms) => { time += ms; } };
}

test("issues a challenge and only accepts one protected submission", async (t) => {
  const { issue, submit } = await fixture(t);
  const challenge = await issue();
  assert.match(challenge.id, /^[a-f0-9]{48}$/);
  assert.equal(challenge.expiresIn, 120);
  assert.equal(challenge.response.headers.get("cache-control"), "no-store");
  assert.match(challenge.response.headers.get("set-cookie"), /HttpOnly; SameSite=Strict/);
  const svg = Buffer.from(challenge.image.split(",")[1], "base64").toString();
  assert.match(svg, /^<svg/);
  assert.doesNotMatch(svg, /ABCD23/);
  const results = await Promise.all([submit(challenge, " abcd23 "), submit(challenge)]);
  assert.deepEqual(results.map((response) => response.status).sort(), [200, 410]);
  assert.deepEqual(await results.find((response) => response.ok).json(), { accepted: true });
});

test("rejects a challenge outside its session and rejects a modified cookie", async (t) => {
  const { issue, submit } = await fixture(t);
  const challenge = await issue();
  const other = await issue();
  assert.equal((await submit(challenge, rightAnswer, other.cookie)).status, 410);
  const changedCookie = challenge.cookie.slice(0, -1) + (challenge.cookie.endsWith("0") ? "1" : "0");
  assert.equal((await submit(challenge, rightAnswer, changedCookie)).status, 410);
  assert.equal((await submit(challenge)).status, 200);
});

test("expires at the time boundary and requires a new challenge", async (t) => {
  const { issue, submit, advance } = await fixture(t);
  const challenge = await issue();
  advance(120_000);
  assert.deepEqual(await (await submit(challenge)).json(), { error: "challenge_unavailable", refresh: true });
  assert.equal((await submit(await issue(challenge.cookie))).status, 200);
});

test("consumes a challenge on the fifth incorrect answer", async (t) => {
  const { issue, submit } = await fixture(t);
  const challenge = await issue();
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const response = await submit(challenge, wrongAnswer);
    assert.equal(response.status, 422);
    assert.deepEqual(await response.json(), { error: "incorrect_answer", refresh: attempt === 5 });
  }
  assert.equal((await submit(challenge)).status, 410);
});

test("limits challenges by session and source and resets the window", async (t) => {
  const { issue, post, advance } = await fixture(t);
  const challenge = await issue();
  for (let i = 0; i < 7; i += 1) await issue(challenge.cookie);
  const sessionLimit = await post("/api/challenges", {}, { cookie: challenge.cookie });
  assert.equal(sessionLimit.status, 429);
  assert.equal(sessionLimit.headers.get("retry-after"), "60");
  for (let i = 0; i < 15; i += 1) await issue();
  assert.equal((await post("/api/challenges", {})).status, 429);
  advance(60_000);
  await issue(challenge.cookie);
});

test("rate limits repeated submission independently of challenge issuance", async (t) => {
  const { issue, post, submit } = await fixture(t);
  const challenge = await issue();
  for (let i = 0; i < 12; i += 1) {
    assert.equal((await post("/api/verify", {}, { cookie: challenge.cookie })).status, 400);
  }
  const blocked = await submit(challenge);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get("retry-after"), "60");
  await issue(challenge.cookie);
});

test("enforces request origin and JSON size and shape", async (t) => {
  const { issue, post, submit, url } = await fixture(t);
  const challenge = await issue();
  const valid = { id: challenge.id, answer: rightAnswer };
  const cookie = challenge.cookie;
  assert.equal((await post("/api/verify", valid, { cookie, origin: "https://example.com" })).status, 403);
  assert.equal((await post("/api/verify", valid, { cookie, origin: null })).status, 403);
  assert.equal((await post("/api/verify", valid, { cookie, headers: { "Sec-Fetch-Site": "cross-site" } })).status, 403);
  assert.equal((await post("/api/verify", valid, { cookie, headers: { "Content-Type": "text/plain" } })).status, 415);
  assert.equal((await post("/api/verify", "{", { cookie })).status, 400);
  assert.equal((await post("/api/verify", { ...valid, answer: "x".repeat(5000) }, { cookie })).status, 413);
  assert.equal((await post("/api/verify", { ...valid, answer: {} }, { cookie })).status, 400);
  assert.equal((await submit(challenge)).status, 200);
  const page = await fetch(url);
  assert.match(page.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.match(await page.text(), /<form id="verification-form">/);
  assert.equal((await fetch(url + "/api/challenges")).status, 405);
});

test("HTTPS origin enables a secure host-only session cookie", async (t) => {
  const { issue } = await fixture(t, { origin: "https://captcha.example.test" });
  const challenge = await issue();
  const cookie = challenge.response.headers.get("set-cookie");
  assert.match(cookie, /^__Host-ac_session=/);
  assert.match(cookie, /; Path=\/; HttpOnly; Secure; SameSite=Strict/);
  assert.doesNotMatch(cookie, /Domain=/i);
});


test("a filled decoy field discards the challenge and limits that session temporarily", async (t) => {
  const { issue, post, submit, advance } = await fixture(t);
  const challenge = await issue();
  const rejected = await post("/api/verify", {
    id: challenge.id, answer: rightAnswer, reference: "filled automatically"
  }, { cookie: challenge.cookie });
  assert.equal(rejected.status, 429);
  assert.equal(rejected.headers.get("retry-after"), "45");
  assert.equal((await post("/api/challenges", {}, { cookie: challenge.cookie })).status, 429);

  const other = await issue();
  assert.equal((await submit(other)).status, 200);
  advance(45_000);
  assert.equal((await submit(challenge)).status, 410);
  assert.equal((await submit(await issue(challenge.cookie))).status, 200);
});

test("repeated failures require two correct codes in the same session", async (t) => {
  const { issue, submit } = await fixture(t);
  const challenge = await issue();
  for (let i = 0; i < 3; i += 1) {
    assert.equal((await submit(challenge, wrongAnswer)).status, 422);
  }
  const first = await submit(challenge);
  assert.equal(first.status, 202);
  const { verification, challenge: next } = await first.json();
  assert.equal(verification, "additional");
  assert.notEqual(next.id, challenge.id);
  assert.equal((await submit(challenge)).status, 410);
  assert.equal((await submit(next, rightAnswer, (await issue()).cookie)).status, 410);
  assert.equal((await submit(next, rightAnswer, challenge.cookie)).status, 200);
  assert.equal((await submit(next, rightAnswer, challenge.cookie)).status, 410);

  const newChallenge = await issue(challenge.cookie);
  assert.equal((await submit(newChallenge)).status, 202);
});

test("source risk persists when a client switches sessions", async (t) => {
  const { issue, submit, advance } = await fixture(t);
  for (let i = 0; i < 4; i += 1) {
    const challenge = await issue();
    assert.equal((await submit(challenge, wrongAnswer)).status, 422);
    assert.equal((await submit(challenge, wrongAnswer)).status, 422);
  }
  assert.equal((await submit(await issue())).status, 202);
  advance(5 * 60_000);
  assert.equal((await submit(await issue())).status, 200);
});

test("speed alone permits a valid answer, while rapid repeated issuance requires another code", async (t) => {
  const { issue, submit, advance } = await fixture(t);
  const first = await issue();
  assert.equal((await submit(first)).status, 200);
  await issue(first.cookie);
  const quick = await issue(first.cookie);
  assert.equal((await submit(quick)).status, 202);
  const ordinary = await issue(first.cookie);
  advance(750);
  assert.equal((await submit(ordinary)).status, 200);
});

test("an enabled provider requires a valid token and serializes verification", async (t) => {
  let release;
  let markStarted;
  const started = new Promise((resolve) => { markStarted = resolve; });
  const turnstile = {
    siteKey: "public-key",
    async verify(token, id) {
      assert.match(id, /^[a-f0-9]{48}$/);
      if (token === "invalid") return false;
      if (token === "unavailable") throw new Error("offline");
      return new Promise((resolve) => {
        release = resolve;
        markStarted();
      });
    }
  };
  const { issue, post, submit } = await fixture(t, { turnstile });
  const challenge = await issue();
  assert.equal(challenge.siteKey, "public-key");
  const send = (providerToken) => post("/api/verify", {
    id: challenge.id, answer: rightAnswer, providerToken
  }, { cookie: challenge.cookie });
  assert.equal((await submit(challenge)).status, 422);
  assert.equal((await send("invalid")).status, 422);
  assert.equal((await send("unavailable")).status, 503);
  const pending = send("valid");
  await started;
  try {
    assert.equal((await send("valid")).status, 409);
  } finally {
    release(true);
  }
  assert.equal((await pending).status, 200);
  assert.equal((await send("valid")).status, 410);
});

test("Turnstile verifier binds responses to site, form action, and challenge", async () => {
  const { createTurnstile } = require("./turnstile");
  const result = { success: true, hostname: "captcha.example.test", action: "verify", cdata: "challenge" };
  let payload = result;
  const validator = createTurnstile({
    origin: "https://captcha.example.test",
    siteKey: "public",
    secret: "private",
    async request(url, options) {
      assert.equal(url, "https://challenges.cloudflare.com/turnstile/v0/siteverify");
      assert.equal(options.body.get("secret"), "private");
      assert.equal(options.body.get("response"), "token");
      assert.equal(options.body.has("remoteip"), false);
      return Response.json(payload);
    }
  });
  assert.equal(await validator.verify("token", "challenge"), true);
  assert.equal(await validator.verify("token", "different"), false);
  payload = { ...result, hostname: "other.example.test" };
  assert.equal(await validator.verify("token", "challenge"), false);
  payload = { ...result, action: "other" };
  assert.equal(await validator.verify("token", "challenge"), false);
  payload = { success: false, "error-codes": ["internal-error"] };
  await assert.rejects(validator.verify("token", "challenge"));
});
