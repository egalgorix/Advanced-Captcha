"use strict";

const form = document.querySelector("#verification-form");
const answer = document.querySelector("#answer");
const image = document.querySelector("#challenge-image");
const placeholder = document.querySelector("#challenge-placeholder");
const refresh = document.querySelector("#refresh");
const submit = document.querySelector("#submit");
const status = document.querySelector("#status");
const reference = document.querySelector("#reference");
const securityCheck = document.querySelector("#security-check");
let providerRequired = false;
let providerToken = "";
let providerWidget = null;
let providerScript;
let busy = false;
let challengeId = null;

function notify(text, kind = "") {
  status.textContent = text;
  status.dataset.kind = kind;
}

function setBusy(value) {
  busy = value;
  form.setAttribute("aria-busy", String(busy));
  refresh.disabled = busy;
  submit.disabled = busy || !challengeId || (providerRequired && !providerToken);
}

async function post(url, data) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  return { response, data: await response.json() };
}

function waitMessage(response) {
  const seconds = Number(response.headers.get("Retry-After"));
  return seconds > 0 ? "Try again in about " + seconds + " seconds." : "Try again shortly.";
}

function clearProvider() {
  if (providerWidget !== null) window.turnstile.remove(providerWidget);
  providerWidget = null;
  providerToken = "";
  providerRequired = false;
  securityCheck.hidden = true;
}

function loadProvider() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (!providerScript) {
    providerScript = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.onload = () => {
        if (window.turnstile) resolve(window.turnstile);
        else reject(new Error("Verification service did not load"));
      };
      script.onerror = () => {
        script.remove();
        reject(new Error("Verification service did not load"));
      };
      document.head.append(script);
    }).catch((error) => {
      providerScript = undefined;
      throw error;
    });
  }
  return providerScript;
}

function renderProvider(id, siteKey) {
  providerRequired = true;
  securityCheck.hidden = false;
  loadProvider().then((provider) => {
    if (challengeId !== id) return;
    providerWidget = provider.render(securityCheck, {
      sitekey: siteKey,
      action: "verify",
      cData: id,
      size: "compact",
      appearance: "interaction-only",
      callback(token) {
        if (challengeId !== id) return;
        providerToken = token;
        setBusy(busy);
      },
      "expired-callback"() {
        if (challengeId !== id) return;
        providerToken = "";
        setBusy(busy);
        if (providerWidget !== null) provider.reset(providerWidget);
      },
      "error-callback"() {
        if (challengeId !== id) return;
        providerToken = "";
        setBusy(busy);
        notify("The security check couldn’t load. Request a new code to try again.", "error");
      }
    });
  }).catch(() => {
    if (challengeId === id) notify("The security check couldn’t load. Request a new code to try again.", "error");
  });
}

function showChallenge(challenge) {
  clearProvider();
  challengeId = challenge.id;
  image.src = challenge.image;
  image.hidden = false;
  placeholder.hidden = true;
  if (challenge.siteKey) renderProvider(challenge.id, challenge.siteKey);
}

function removeChallenge(text) {
  clearProvider();
  challengeId = null;
  image.hidden = true;
  image.removeAttribute("src");
  placeholder.hidden = false;
  placeholder.textContent = text;
}

async function loadChallenge({ focus = false, previousMessage = "" } = {}) {
  setBusy(true);
  removeChallenge("Loading code…");
  answer.value = "";
  notify(previousMessage || "Loading a new code.");
  try {
    const { response, data } = await post("/api/challenges", {});
    if (!response.ok) {
      removeChallenge("Code unavailable");
      notify("Couldn’t load a new code. " + waitMessage(response), "error");
      return;
    }
    showChallenge(data);
    notify(previousMessage || "");
    if (focus) answer.focus();
  } catch {
    removeChallenge("Code unavailable");
    notify("Couldn’t reach the server. Request a new code to try again.", "error");
  } finally {
    setBusy(false);
  }
}

refresh.addEventListener("click", () => loadChallenge({ focus: true }));

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!challengeId || submit.disabled) return;
  setBusy(true);
  notify("Verifying…");
  try {
    const { response, data } = await post("/api/verify", {
      id: challengeId,
      answer: answer.value,
      reference: reference.value,
      ...(providerRequired && { providerToken })
    });
    if (response.ok && data.accepted) {
      removeChallenge("Verified");
      form.reset();
      notify("Verification complete.", "success");
      return;
    }
    if (response.status === 202 && data.verification === "additional") {
      showChallenge(data.challenge);
      answer.value = "";
      notify("One more check. Enter the new code.");
      answer.focus();
      return;
    }
    if (data.error === "provider_rejected" || data.error === "provider_required" ||
        (response.status === 503 && providerRequired)) {
      providerToken = "";
      if (providerWidget !== null) window.turnstile.reset(providerWidget);
      notify("The security check couldn’t be completed. " + waitMessage(response), "error");
      return;
    }
    if (data.refresh) {
      await loadChallenge({ focus: true, previousMessage: "That code is no longer valid. Enter the new one." });
      return;
    }
    if (response.status === 422) {
      answer.select();
      notify("That code doesn’t match. Try again.", "error");
      return;
    }
    if (response.status === 400) {
      notify("Enter a six-character code.", "error");
      return;
    }
    notify("Couldn’t verify the code. " + waitMessage(response), "error");
  } catch {
    notify("Couldn’t reach the server. Check your connection and try again.", "error");
  } finally {
    setBusy(false);
  }
});

loadChallenge();
