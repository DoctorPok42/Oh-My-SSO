// Account console: what plain HTML cannot do. Every page works without this
// file, except "Add a passkey" (the browser's WebAuthn API is JavaScript).
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);

  // --- times: shown in UTC by the server, here in the reader's time zone.
  const full = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
  function localTimes(root) {
    for (const t of root.querySelectorAll("time[datetime]")) {
      const d = new Date(t.dateTime);
      if (Number.isNaN(d.getTime()) || t.dataset.local) continue;
      t.title = t.textContent;
      t.textContent = (t.dataset.format === "date" ? date : full).format(d);
      t.dataset.local = "1";
    }
  }
  localTimes(document);
  // Content swapped in by htmx.
  document.body.addEventListener("htmx:load", (ev) => localTimes(ev.detail.elt));

  // --- menus (<details>): one open at a time, closed by a click elsewhere
  // or Escape.
  document.addEventListener("click", (ev) => {
    for (const d of document.querySelectorAll("details.menu[open]")) {
      if (!d.contains(ev.target)) d.open = false;
    }
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    for (const d of document.querySelectorAll("details.menu[open]")) {
      d.open = false;
      d.querySelector("summary").focus();
    }
  });

  // --- theme: Light / Dark / System, as in the admin console
  // (console/theme-toggle.tsx). Applied at once on <html>, remembered for a
  // year in the cookie the server reads (no flash of the other theme).
  const toggle = $("theme-toggle");
  if (toggle) {
    toggle.hidden = false;
    toggle.addEventListener("click", (ev) => {
      const b = ev.target.closest("button[data-theme]");
      if (!b) return;
      const theme = b.dataset.theme;
      const html = document.documentElement;
      html.classList.remove("light", "dark");
      if (theme !== "system") html.classList.add(theme);
      for (const o of toggle.querySelectorAll("button[data-theme]")) o.setAttribute("aria-checked", String(o === b));
      const secure = location.protocol === "https:" ? "; Secure" : "";
      document.cookie = `omsso_theme=${theme}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
    });
  }

  // --- backup codes: copy, download.
  function codesText() {
    const list = $("codes");
    return list ? [...list.querySelectorAll("li")].map((li) => li.textContent.trim()).join("\n") + "\n" : "";
  }
  document.addEventListener("click", async (ev) => {
    const copy = ev.target.closest("[data-copy-codes]");
    if (copy) {
      try {
        await navigator.clipboard.writeText(codesText());
        copy.textContent = "Copied";
      } catch {
        copy.textContent = "Select the codes to copy them";
      }
      return;
    }
    const dl = ev.target.closest("[data-download-codes]");
    if (dl) {
      const url = URL.createObjectURL(new Blob([codesText()], { type: "text/plain" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = "backup-codes.txt";
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  });

  // --- passkey or security key: the server speaks base64url JSON, the
  // browser API wants ArrayBuffers (same helpers as the sign-in page).
  const form = $("passkey-form");
  if (!form) return;
  const api = form.dataset.api;
  const base = form.dataset.base;
  const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const creationOptions = (o) => {
    const pk = o.publicKey;
    return { ...pk, challenge: dec(pk.challenge), user: { ...pk.user, id: dec(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: dec(c.id) })) };
  };
  const credentialJSON = (cred) => {
    if (cred.toJSON) return cred.toJSON();
    const r = cred.response;
    return {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: enc(r.clientDataJSON), attestationObject: enc(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : [],
      },
    };
  };
  const messages = {
    step_up_required: "For your security, confirm it's you first: reload this page.",
    recent_login_required: "For your security, sign in again first: reload this page.",
    passkey_already_registered: "This device or key is already on your account.",
    webauthn_rejected: "Your device's answer was not accepted. Try again.",
    webauthn_ceremony_expired: "This attempt has expired. Try again.",
    passkeys_disabled: "Passkeys are not enabled on this server.",
    unauthenticated: "Your session has ended. Reload the page to sign in again.",
    rate_limited: "Too many attempts. Wait a few minutes, then try again.",
  };
  const showError = (code) => {
    $("passkey-status").hidden = true;
    const el = $("passkey-error");
    el.textContent = messages[code] || "Something went wrong. Please try again.";
    el.hidden = false;
  };
  const post = async (path, body) => {
    const res = await fetch(api + path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    return { status: res.status, data: data || {} };
  };

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("passkey-error").hidden = true;
    if (!window.PublicKeyCredential) return showError("unsupported");
    const button = $("passkey-add");
    button.disabled = true;
    try {
      const kind = form.querySelector("input[name=kind]:checked").value;
      const opts = await post("/account/mfa/webauthn/register/options", { kind, name: $("passkey-name").value.trim() });
      if (opts.status !== 200) return showError(opts.data.error);
      const status = $("passkey-status");
      status.textContent = "Follow the instructions of your browser or device...";
      status.hidden = false;
      let cred;
      try {
        cred = await navigator.credentials.create({ publicKey: creationOptions(opts.data) });
      } catch (e) {
        status.hidden = true;
        if (e && e.name === "InvalidStateError") return showError("passkey_already_registered");
        return showError(e && e.name === "NotAllowedError" ? "cancelled" : "");
      }
      const res = await post("/account/mfa/webauthn/register/verify", credentialJSON(cred));
      if (res.status !== 200) return showError(res.data.error);
      const codes = res.data.backup_codes || [];
      if (!codes.length) {
        location.assign(base + "/security?done=passkey");
        return;
      }
      // First second step: its backup codes, shown once.
      const list = $("codes");
      for (const c of codes) {
        const li = document.createElement("li");
        li.textContent = c;
        list.append(li);
      }
      form.hidden = true;
      $("passkey-codes").hidden = false;
      $("passkey-codes").querySelector("h2").focus();
    } finally {
      button.disabled = false;
    }
  });
  messages.cancelled = "The request was cancelled or timed out. Try again.";
  messages.unsupported = "This browser cannot use passkeys.";
})();
