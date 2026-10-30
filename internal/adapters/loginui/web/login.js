(() => {
  "use strict";
  const app = document.getElementById("app");
  if (!app) return;
  const $ = (id) => document.getElementById(id);
  const base = app.dataset.base;
  const clientParam = app.dataset.clientParam === "entity_id" ? "entity_id" : "client_id";
  const clientId = app.dataset.clientId;
  const passkeysOn = app.dataset.passkeys === "on";

  // One method on screen at a time, "Try another way" lists the others
  //   first   who are you: a passkey (or security key) alone, or the password
  //   second  after the password: passkey, authenticator app, backup code
  //   stepup  the session exists, the application wants a second factor
  let step = app.dataset.mode === "stepup" ? "stepup" : "first";
  let methods = firstStepMethods(null);
  let current = app.dataset.mode === "login" ? "password" : null;
  let tile = null; // the "Pick an account" tile being signed in: {account, identifier, methods}
  const skipped = new Set(); // methods the user moved away from with "Try another way"
  // The passkey prompt: at most one at a time, and it never holds the page.
  let prompt = null; // {ctrl, done}: the browser's prompt in progress
  let attempt = 0; // +1 at each screen change: an older prompt's result is ignored

  const messages = {
    invalid_credentials: "Wrong username or password.",
    invalid_request: "Please fill in every field.",
    invalid_mfa_code: "Wrong code. Try again.",
    mfa_challenge_expired: "This attempt has expired. Please sign in again.",
    rate_limited: "Too many attempts. Wait a few minutes, then try again.",
    method_not_allowed: "This application does not accept this method.",
    webauthn_ceremony_expired: "The passkey request has expired. Try again.",
    webauthn_rejected: "The passkey was not accepted.",
    passkey_rejected: "This passkey or security key could not sign you in.",
    passkey_unavailable: "This account cannot use a passkey here. Enter your password.",
    passkeys_disabled: "Passkeys are not enabled on this server.",
    unauthenticated: "Your session has ended. Please sign in again.",
    unknown_client: "This application is not available.",
    access_suspended: "Your access is temporarily suspended. Contact your administrator.",
    client_unavailable: "This application is temporarily unavailable. Try again later.",
  };

  // What "Try another way" offers, in the server's order (best first).
  const labels = {
    passkey: "Use a passkey or security key",
    password: "Enter your password",
    totp: "Get a code from your authenticator app",
    backup_code: "Use a backup code",
  };

  function showError(code, remaining) {
    let text = messages[code] || "Something went wrong. Please try again.";
    if (typeof remaining === "number") text += ` (${remaining} attempt${remaining === 1 ? "" : "s"} left)`;
    $("error").textContent = text;
    $("error").hidden = false;
  }
  const clearError = () => { $("error").hidden = true; };

  const post = (path, body) => postURL(base + path, body);

  async function postURL(url, body) {
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    return { status: res.status, data: data || {} };
  }

  // The server decides what comes next.
  const done = () => location.reload();

  function busy(form, on) {
    for (const b of form.querySelectorAll("button")) b.disabled = on;
  }


  // First step: a tile brings its account's methods ("passkey,password");
  // without a tile, the password, or any passkey of the browser.
  function firstStepMethods(fromTile) {
    const known = (fromTile || "").split(",").filter((m) => m === "password" || (m === "passkey" && passkeysOn));
    if (fromTile !== null && known.length) return known;
    return passkeysOn ? ["password", "passkey"] : ["password"];
  }

  // Second step and step-up: the server's methods, best first. A passkey and
  // a security key are one choice; backup codes are named "backup_code".
  function secondStepMethods(serverMethods) {
    const out = [];
    for (const m of serverMethods || []) {
      const ui = m === "passkey" || m === "webauthn" ? "passkey" : m === "backup_codes" ? "backup_code" : m;
      if (ui === "passkey" && !passkeysOn) continue;
      if (labels[ui] && !out.includes(ui)) out.push(ui);
    }
    return out;
  }

  // The method a step starts with: the best one the user did not move away
  // from, and never the backup codes while something else exists.
  function pickDefault() {
    const fresh = methods.filter((m) => !skipped.has(m) && m !== "backup_code");
    return fresh[0] || methods.find((m) => m !== "backup_code") || methods[0];
  }


  const accounts = $("accounts");
  const remember = $("remember");
  const rememberBox = $("remember-me");
  const rememberChecked = () => !!(rememberBox && rememberBox.checked);

  // "Don't ask again on this device" belongs to the second step, when the
  // server offers it (trust_device_days: the realm allows it and this
  // application does not require a second factor).
  const trust = $("trust");
  const trustBox = $("trust-device");
  let trustDays = 0;
  const trustChecked = () => step === "second" && trustDays > 0 && trustBox.checked;

  function placeTrust(section, before) {
    const on = step === "second" && trustDays > 0;
    trust.hidden = !on;
    if (on) section.insertBefore(trust, before);
  }

  function hideAll() {
    cancelPasskey(); // leaving the screen closes its passkey prompt
    trust.hidden = true;
    accounts.hidden = true;
    $("password-form").hidden = true;
    $("passkey-step").hidden = true;
    $("code-form").hidden = true;
    $("other-ways").hidden = true;
  }

  function updateLinks(choosing) {
    const another = $("try-another");
    another.hidden = choosing || methods.length < 2;
    const back = $("back-to-accounts");
    if (back) back.hidden = step !== "first" || !document.querySelector(".account");
    $("step-links").hidden = another.hidden && (!back || back.hidden);
  }

  // "Keep me signed in" belongs to the first step, whichever method.
  function placeRemember(section, before) {
    if (!remember) return;
    remember.hidden = step !== "first";
    if (step === "first") section.insertBefore(remember, before);
  }

  // show puts one method on screen. launch: start the passkey right away
  // (only after a click: browsers may refuse a passkey request otherwise).
  function show(method, launch) {
    clearError();
    hideAll();
    current = method;
    $("title").textContent = step === "first" ? "Sign in" : "Confirm it's you";

    if (method === "password") {
      const form = $("password-form");
      form.hidden = false;
      placeRemember(form, $("password-submit"));
      ($("identifier").value ? $("password") : $("identifier")).focus();
    } else if (method === "passkey") {
      const section = $("passkey-step");
      section.hidden = false;
      placeRemember(section, $("passkey-btn"));
      placeTrust(section, $("passkey-btn"));
      const who = step === "first" && tile ? ` to sign in as ${tile.identifier}` : step === "first" ? " to sign in" : " to confirm it's you";
      $("passkey-hint").textContent = `Use your passkey or security key${who}.`;
      $("passkey-status").hidden = true;
      $("passkey-btn").textContent = "Continue";
      $("passkey-btn").disabled = false;
      // The prompt covers the page: with "Don't ask again on this device"
      // on screen, it waits for "Continue" so the box can be ticked first.
      if (launch && trust.hidden) runPasskey();
      else $("passkey-btn").focus();
    } else {
      const form = $("code-form");
      form.hidden = false;
      placeTrust(form, form.querySelector("button[type=submit]"));
      const backup = method === "backup_code";
      $("code-hint").textContent = backup ? "Enter one of your backup codes." : "Enter the code from your authenticator app.";
      $("code-label").textContent = backup ? "Backup code" : "Code";
      $("code").setAttribute("inputmode", backup ? "text" : "numeric");
      $("code").value = "";
      $("code").focus();
    }
    updateLinks(false);
  }

  // "Try another way": every method of this step, the current one marked.
  $("try-another").addEventListener("click", () => {
    clearError();
    hideAll();
    if (remember) remember.hidden = true;
    $("ways-hint").textContent = step === "first" ? "Choose how you want to sign in:" : "Choose how you want to confirm it's you:";
    const list = $("ways");
    list.replaceChildren();
    for (const m of methods) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.className = "btn btn-secondary btn-md btn-block way";
      b.dataset.method = m;
      b.textContent = labels[m];
      if (m === current) b.setAttribute("aria-current", "true");
      b.addEventListener("click", () => {
        if (m !== current && current) skipped.add(current);
        show(m, true);
      });
      li.append(b);
      list.append(li);
    }
    $("other-ways").hidden = false;
    updateLinks(true);
    list.querySelector("button").focus();
  });

  function startSecondStep(serverMethods, nextStep, offerDays) {
    step = nextStep;
    methods = secondStepMethods(serverMethods);
    trustDays = nextStep === "second" ? offerDays || 0 : 0;
    trustBox.checked = false;
    $("trust-device-hint").textContent = `For ${trustDays} days, unless an application requires a second factor. ` +
      "Leave this unchecked on a shared or public computer.";
    if (!methods.length) {
      hideAll();
      updateLinks(true);
      return showError("method_not_allowed");
    }
    const m = pickDefault();
    show(m, m === "passkey" && nextStep === "second" && !skipped.has("passkey"));
  }

  // Back to the password when the attempt is over (challenge expired).
  function restart(code) {
    step = "first";
    tile = null;
    skipped.clear();
    methods = firstStepMethods(null);
    show("password", false);
    if (code) showError(code);
  }


  $("password-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearError();
    const form = ev.currentTarget;
    busy(form, true);
    const body = {
      identifier: $("identifier").value,
      password: $("password").value,
      remember_me: rememberChecked(),
      [clientParam]: clientId,
    };
    // From a tile: the server remembers the password was chosen there.
    if (tile) body.account_id = tile.account;
    const { status, data } = await post("/auth/login", body);
    busy(form, false);
    if (status !== 200) return showError(data.error);
    if (data.status === "mfa_required") return startSecondStep(data.methods, "second", data.trust_device_days);
    done(); // "authenticated" or "mfa_enrollment_required"
  });

  $("code-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearError();
    const form = ev.currentTarget;
    const method = current === "backup_code" ? "backup_code" : "totp";
    busy(form, true);
    const path = step === "stepup" ? "/auth/step-up" : "/auth/mfa/verify";
    const body = { method, code: $("code").value.trim() };
    if (trustChecked()) body.trust_device = true;
    const { status, data } = await post(path, body);
    busy(form, false);
    if (status === 200) return done();
    if (data.error === "mfa_challenge_expired") return restart(data.error);
    $("code").value = "";
    showError(data.error, data.attempts_remaining);
  });

  // --- passkeys: the server speaks base64url JSON, the browser API wants
  // ArrayBuffers (same helpers as the account console, account.js).
  const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const requestOptions = (o) => {
    const pk = o.publicKey;
    return { ...pk, challenge: dec(pk.challenge), allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: dec(c.id) })) };
  };
  const credentialJSON = (cred) => {
    if (cred.toJSON) return cred.toJSON();
    const r = cred.response;
    return {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: enc(r.clientDataJSON), authenticatorData: enc(r.authenticatorData),
        signature: enc(r.signature), userHandle: r.userHandle ? enc(r.userHandle) : null,
      },
    };
  };

  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // cancelPasskey closes the prompt in progress, if any. The browser then
  // rejects it with an AbortError, which the old attempt ignores.
  function cancelPasskey() {
    attempt++;
    if (prompt) prompt.ctrl.abort();
  }

  // runPasskey starts a new prompt. A prompt that never answers (a passkey
  // app closed without telling the browser) does not block anything: "Try
  // again", "Try another way" and the other links stay usable and close it.
  async function runPasskey() {
    clearError();
    const old = prompt;
    cancelPasskey();
    const mine = attempt;
    if (old) await Promise.race([old.done, wait(1000)]); // the browser accepts one prompt at a time
    if (mine !== attempt) return; // the user went elsewhere meanwhile
    const ctrl = new AbortController();
    let finished;
    const p = { ctrl, done: new Promise((resolve) => { finished = resolve; }) };
    prompt = p;
    try {
      await passkeyCeremony(ctrl.signal, () => mine === attempt);
    } finally {
      finished();
      if (prompt === p) prompt = null;
    }
  }

  // passkeyCeremony: options, the browser's prompt, the answer. live() is
  // false once the user left this attempt: nothing it does then shows.
  async function passkeyCeremony(signal, live) {
    const btn = $("passkey-btn");
    const status = $("passkey-status");
    // first: sign in without password; second: the challenge of the
    // password (sso_mfa cookie); stepup: the current session.
    const prefix = step === "first" ? "/auth/passkey" : step === "second" ? "/auth/mfa/webauthn" : "/auth/step-up/webauthn";
    const body = step === "first" ? { [clientParam]: clientId } : {};
    if (step === "first" && tile) body.account_id = tile.account;
    if (step === "first" && !clientId) delete body[clientParam];

    btn.disabled = true; // only while we talk to the server
    const opts = await post(prefix + "/options", body);
    btn.disabled = false;
    if (!live()) return;
    if (opts.status !== 200) {
      if (step === "first" && (opts.data.error === "passkey_unavailable" || opts.data.error === "not_found")) {
        // Nothing this account can use here anymore: its password.
        methods = methods.filter((m) => m !== "passkey");
        show("password", false);
        return showError("passkey_unavailable");
      }
      if (opts.data.error === "mfa_challenge_expired") return restart(opts.data.error);
      return showError(opts.data.error);
    }

    // The prompt is open: "Try again" restarts it, whatever happened to it.
    btn.textContent = "Try again";
    status.textContent = "Waiting for your passkey or security key...";
    status.hidden = false;
    let cred;
    try {
      cred = await navigator.credentials.get({ publicKey: requestOptions(opts.data), signal });
    } catch {
      if (!live()) return; // closed on purpose: the user went elsewhere
      // Cancelled, timed out, or the browser wanted a click first: the
      // user tries again (a click) or takes another way.
      status.textContent = "The request was cancelled or timed out.";
      btn.focus();
      return;
    }
    if (!live()) return; // answered too late: the user went elsewhere
    status.hidden = true;
    const answer = step === "first" ? { credential: credentialJSON(cred), remember_me: rememberChecked() }
      : step === "second" ? { credential: credentialJSON(cred), trust_device: trustChecked() }
      : credentialJSON(cred);
    btn.disabled = true;
    const res = await post(prefix + "/verify", answer);
    btn.disabled = false;
    if (res.status === 200) return done();
    if (!live()) return;
    if (res.data.error === "mfa_challenge_expired") return restart(res.data.error);
    showError(res.data.error, res.data.attempts_remaining);
  }

  $("passkey-btn").addEventListener("click", () => runPasskey());

  // A signed-out tile starts its account's best method: the passkey when
  // it has one this application accepts (like "Use a passkey or security
  // key"), else the password form with the account filled in. "Keep me
  // signed in" is ticked: it was ticked on this device before. The
  // signed-in tile goes on with this browser's session.

  function startFirstStep(fromTile, identifier, rememberOn) {
    step = "first";
    skipped.clear();
    tile = fromTile;
    methods = firstStepMethods(fromTile ? fromTile.methods : null);
    $("identifier").value = identifier || "";
    if (rememberBox) rememberBox.checked = !!rememberOn;
    const m = methods[0];
    show(m, m === "passkey");
  }

  function showAccounts() {
    clearError();
    hideAll();
    if (remember) remember.hidden = true;
    tile = null;
    accounts.hidden = false;
    $("title").textContent = "Pick an account";
    $("step-links").hidden = true;
  }

  for (const btn of document.querySelectorAll(".account-pick")) {
    btn.addEventListener("click", async () => {
      if (btn.dataset.signedIn !== "on") {
        return startFirstStep({ account: btn.dataset.account, identifier: btn.dataset.identifier, methods: btn.dataset.methods || "" },
          btn.dataset.identifier, true);
      }
      clearError();
      btn.disabled = true;
      const { status, data } = await postURL(app.dataset.continueUrl, {
        id: app.dataset.requestId,
        token: app.dataset.continueToken,
      });
      if (status === 204) return done();
      btn.disabled = false;
      showError(data.error);
    });
  }

  for (const btn of document.querySelectorAll(".forget")) {
    btn.addEventListener("click", async () => {
      clearError();
      btn.disabled = true;
      const { status, data } = await post("/auth/accounts/forget", { account_id: btn.dataset.account });
      if (status !== 204 && status !== 404) {
        btn.disabled = false;
        return showError(data.error);
      }
      if (btn.dataset.signedIn === "on") return done(); // signed out too
      btn.closest("li").remove();
      if (!document.querySelector(".account")) startFirstStep(null, "", false);
    });
  }

  const other = $("other-account");
  if (other) other.addEventListener("click", () => startFirstStep(null, "", false));
  const back = $("back-to-accounts");
  if (back) back.addEventListener("click", showAccounts);

  if (current === "password") updateLinks(false);

  // Step-up: the session exists, the application wants a (recent) second
  // factor. Offer the factors the user has AND the application accepts,
  // best first. No click yet: the passkey waits for "Continue".
  if (step === "stepup") {
    (async () => {
      let serverMethods = ["passkey", "webauthn", "totp", "backup_codes"];
      try {
        const res = await fetch(`${base}/auth/mfa/status?${clientParam}=${encodeURIComponent(clientId)}`,
          { credentials: "same-origin", headers: { Accept: "application/json" } });
        if (res.ok) {
          const st = await res.json();
          const allowed = st.allowed_methods || [];
          serverMethods = (st.enrolled_methods || []).filter((m) => !allowed.length || allowed.includes(m));
        }
      } catch { /* keep the defaults */ }
      startSecondStep(serverMethods, "stepup");
    })();
  }
})();
