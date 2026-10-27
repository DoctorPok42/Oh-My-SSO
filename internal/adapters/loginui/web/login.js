(() => {
  "use strict";
  const app = document.getElementById("app");
  if (!app) return;
  const $ = (id) => document.getElementById(id);
  const base = app.dataset.base;
  const clientParam = app.dataset.clientParam === "entity_id" ? "entity_id" : "client_id";
  const clientId = app.dataset.clientId;
  const passkeysOn = app.dataset.passkeys === "on";
  let stage = app.dataset.mode === "stepup" ? "stepup" : "password"; // password | mfa | stepup

  const messages = {
    invalid_credentials: "Wrong username or password.",
    invalid_request: "Please fill in every field.",
    invalid_mfa_code: "Wrong code. Try again.",
    mfa_challenge_expired: "This attempt has expired. Please sign in again.",
    rate_limited: "Too many attempts. Wait a few minutes, then try again.",
    method_not_allowed: "This application does not accept this method.",
    webauthn_ceremony_expired: "The passkey request has expired. Try again.",
    webauthn_rejected: "The passkey was not accepted.",
    passkeys_disabled: "Passkeys are not enabled on this server.",
    unauthenticated: "Your session has ended. Please sign in again.",
    unknown_client: "This application is not available.",
  };

  function showError(code, remaining) {
    let text = messages[code] || "Something went wrong. Please try again.";
    if (typeof remaining === "number") text += ` (${remaining} attempt${remaining === 1 ? "" : "s"} left)`;
    $("error").textContent = text;
    $("error").hidden = false;
  }
  const clearError = () => { $("error").hidden = true; };

  async function post(path, body) {
    const res = await fetch(base + path, {
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

  function showSecondFactor(methods) {
    const codes = methods.filter((m) => m === "totp" || m === "backup_codes");
    const passkey = passkeysOn && methods.some((m) => m === "passkey" || m === "webauthn");
    $("password-form").hidden = true;
    $("code-form").hidden = codes.length === 0;
    $("method-choice").hidden = !(codes.includes("totp") && codes.includes("backup_codes"));
    if (!codes.includes("totp") && codes.includes("backup_codes")) {
      document.querySelector('input[value="backup_code"]').checked = true;
      $("code-hint").textContent = "Enter one of your backup codes.";
    }
    $("passkey").hidden = !passkey;
    document.querySelector("#passkey .or").hidden = codes.length === 0;
    if (codes.length) $("code").focus();
    if (!codes.length && !passkey) showError("method_not_allowed");
  }

  $("password-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearError();
    const form = ev.currentTarget;
    busy(form, true);
    const remember = $("remember-me");
    const { status, data } = await post("/auth/login", {
      identifier: $("identifier").value,
      password: $("password").value,
      remember_me: !!(remember && remember.checked),
      [clientParam]: clientId,
    });
    busy(form, false);
    if (status !== 200) return showError(data.error);
    if (data.status === "mfa_required") {
      stage = "mfa";
      $("title").textContent = "Confirm it's you";
      return showSecondFactor(data.methods || []);
    }
    done(); // "authenticated" or "mfa_enrollment_required"
  });

  $("code-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearError();
    const form = ev.currentTarget;
    const checked = document.querySelector('input[name="method"]:checked');
    const method = checked ? checked.value : "totp";
    busy(form, true);
    const path = stage === "stepup" ? "/auth/step-up" : "/auth/mfa/verify";
    const { status, data } = await post(path, { method, code: $("code").value.trim() });
    busy(form, false);
    if (status === 200) return done();
    if (data.error === "mfa_challenge_expired") {
      stage = "password";
      $("code-form").hidden = true;
      $("passkey").hidden = true;
      $("password-form").hidden = false;
    }
    $("code").value = "";
    showError(data.error, data.attempts_remaining);
  });

  // --- passkeys: the server speaks base64url JSON, the browser API wants
  // ArrayBuffers (same helpers as the /dev/mfa page).
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

  $("passkey-btn").addEventListener("click", async () => {
    clearError();
    const prefix = stage === "stepup" ? "/auth/step-up/webauthn" : "/auth/mfa/webauthn";
    const opts = await post(prefix + "/options", {});
    if (opts.status !== 200) return showError(opts.data.error);
    let cred;
    try {
      cred = await navigator.credentials.get({ publicKey: requestOptions(opts.data) });
    } catch {
      return showError("webauthn_rejected");
    }
    const { status, data } = await post(prefix + "/verify", credentialJSON(cred));
    if (status === 200) return done();
    showError(data.error);
  });

  // Step-up: the session exists, the application wants a (recent) second
  // factor. Offer the factors the user has AND the application accepts.
  if (stage === "stepup") {
    (async () => {
      let methods = ["totp", "backup_codes", "passkey", "webauthn"];
      try {
        const res = await fetch(`${base}/auth/mfa/status?${clientParam}=${encodeURIComponent(clientId)}`,
          { credentials: "same-origin", headers: { Accept: "application/json" } });
        if (res.ok) {
          const st = await res.json();
          const allowed = st.allowed_methods || [];
          methods = (st.enrolled_methods || []).filter((m) => !allowed.length || allowed.includes(m));
        }
      } catch { /* keep the defaults */ }
      showSecondFactor(methods);
    })();
  }
})();
