// "Forgot password" and "choose a new password" pages (Step 12).
//
//   forgot   POST {base}/auth/forgot-password  {identifier}       → always 202
//   reset    POST {base}/auth/reset-password   {token, password}  → 200 or error
//
// The reset token is read from the URL fragment (#token=...): browsers never
// send the fragment to the server, so the token cannot leak into access
// logs or a Referer header. Right after reading it, the fragment is removed
// from the address bar (and from history) with history.replaceState.
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);

  const messages = {
    invalid_request: "Please fill in every field.",
    rate_limited: "Too many requests. Wait a few minutes, then try again.",
    invalid_or_expired_token: "This link is invalid, was already used, or has expired. Ask for a new one.",
    password_too_short: "This password is too short.",
    password_too_long: "This password is too long.",
    password_matches_identity: "Your password must not be your username or e-mail.",
    passwords_differ: "The two passwords are not the same.",
  };

  function showError(code) {
    $("error").textContent = messages[code] || "Something went wrong. Please try again.";
    $("error").hidden = false;
  }
  const clearError = () => { $("error").hidden = true; };

  async function post(base, path, body) {
    const res = await fetch(base + path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    return { status: res.status, data: data || {} };
  }

  function busy(form, on) {
    for (const b of form.querySelectorAll("button")) b.disabled = on;
  }

  // --- forgot password ---------------------------------------------------------
  const forgot = $("forgot");
  if (forgot) {
    const base = forgot.dataset.base;
    $("back").addEventListener("click", () => history.back());
    $("forgot-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearError();
      const form = ev.currentTarget;
      busy(form, true);
      try {
        const { status, data } = await post(base, "/auth/forgot-password", { identifier: $("identifier").value.trim() });
        if (status !== 202) return showError(data.error);
        form.hidden = true;
        $("sent").hidden = false;
      } catch {
        showError();
      } finally {
        busy(form, false);
      }
    });
  }

  // --- choose a new password -----------------------------------------------------
  const reset = $("reset");
  if (reset) {
    const base = reset.dataset.base;
    const min = Number(reset.dataset.min) || 12;
    const token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);

    const form = $("reset-form");
    if (!token) {
      form.hidden = true;
      $("new-link").hidden = false;
      showError("invalid_or_expired_token");
      return;
    }
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearError();
      const password = $("password").value;
      if (password !== $("confirm").value) return showError("passwords_differ");
      if ([...password].length < min) return showError("password_too_short");
      busy(form, true);
      try {
        const { status, data } = await post(base, "/auth/reset-password", { token, password });
        if (status === 200) {
          form.hidden = true;
          $("done").hidden = false;
          return;
        }
        showError(data.error);
        if (data.error === "invalid_or_expired_token") {
          form.hidden = true;
          $("new-link").hidden = false;
        }
      } catch {
        showError();
      } finally {
        busy(form, false);
      }
    });
  }
})();
