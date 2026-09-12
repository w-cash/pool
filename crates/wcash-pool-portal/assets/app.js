"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
let authMode = "login";

function csrfToken() {
  const row = document.cookie.split(";").map((value) => value.trim()).find((value) => value.startsWith("__Host-zecwec_csrf="));
  return row ? row.split("=").slice(1).join("=") : "";
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("content-type", "application/json");
  if (options.method && !["GET", "HEAD"].includes(options.method)) headers.set("x-csrf-token", csrfToken());
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("json") ? await response.json() : null;
  if (!response.ok) throw new Error(body?.message || `Request failed (${response.status})`);
  return body;
}

function showAuthenticated(account) {
  $("#auth-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  $("#sign-out").classList.remove("hidden");
  $("#account-name").textContent = account.username;
  refreshOverview();
  refreshWorkers();
  refreshPayouts();
}

function showSignedOut() {
  $("#auth-view").classList.remove("hidden");
  $("#app-view").classList.add("hidden");
  $("#sign-out").classList.add("hidden");
  $("#account-name").textContent = "";
}

async function refreshOverview() {
  try {
    const data = await api("/api/v1/overview");
    $("#pool-hashrate").textContent = data.hashrate_sol_s?.toLocaleString() ?? "—";
    $("#active-workers").textContent = data.active_workers?.toLocaleString() ?? "—";
    $("#wcash-height").textContent = data.wcash_height?.toLocaleString() ?? "—";
    $("#zcash-height").textContent = data.zcash_height?.toLocaleString() ?? "—";
    const revision = data.fee_policy_revision ? ` · policy v${data.fee_policy_revision}` : "";
    $("#wec-fee").textContent = `Pool fee ${data.wec_fee_bps == null ? "—" : `${(data.wec_fee_bps / 100).toFixed(2)}%`}${revision}`;
    $("#zec-fee").textContent = `Pool fee ${data.zec_fee_bps == null ? "—" : `${(data.zec_fee_bps / 100).toFixed(2)}%`}${revision}`;
    $("#data-state").textContent = data.available ? "Live" : "Projection offline";
    $("#data-state").className = `status ${data.available ? "ok" : "warning"}`;
  } catch (_) {
    $("#data-state").textContent = "Unavailable";
  }
}

async function refreshWorkers() {
  try {
    const { workers } = await api("/api/v1/workers");
    const body = $("#workers-body");
    body.replaceChildren();
    if (!workers.length) {
      const row = body.insertRow();
      const cell = row.insertCell(); cell.colSpan = 5; cell.className = "empty"; cell.textContent = "No workers yet.";
      return;
    }
    workers.forEach((worker) => {
      const row = body.insertRow();
      [worker.label, worker.mining_username, worker.revoked_at ? "Revoked" : "Ready", new Date(worker.created_at * 1000).toLocaleString()].forEach((value) => { const cell = row.insertCell(); cell.textContent = value; });
      const action = row.insertCell();
      if (!worker.revoked_at) {
        const button = document.createElement("button"); button.className = "button quiet"; button.textContent = "Revoke";
        button.addEventListener("click", async () => { await api(`/api/v1/workers/${worker.id}`, { method: "DELETE" }); refreshWorkers(); });
        action.append(button);
      }
    });
  } catch (_) { /* Signed-out startup is expected. */ }
}

async function refreshPayouts() {
  try {
    const { settings } = await api("/api/v1/settings/payouts");
    settings.forEach((setting) => {
      const form = $(`.payout-form[data-asset="${setting.asset}"]`);
      const result = $(".setting-result", form);
      if (setting.active_destination) result.textContent = `Active: ${setting.active_destination} · revision ${setting.revision}`;
      if (setting.pending_destination) result.textContent += ` · pending ${setting.pending_destination}`;
      if (setting.threshold_zat) form.elements.threshold_zat.value = setting.threshold_zat;
      form.elements.automatic.checked = setting.automatic;
    });
  } catch (_) { /* Signed-out startup is expected. */ }
}

$$('[data-auth-mode]').forEach((button) => button.addEventListener("click", () => {
  authMode = button.dataset.authMode;
  $$('[data-auth-mode]').forEach((item) => item.classList.toggle("active", item === button));
  $("#auth-submit").textContent = authMode === "login" ? "Sign in" : "Create account";
  $("#totp-login-field").classList.toggle("hidden", authMode !== "login");
  $("#auth-form").elements.password.autocomplete = authMode === "login" ? "current-password" : "new-password";
}));

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget; const error = $("#auth-error"); error.classList.add("hidden");
  const payload = { username: form.elements.username.value, password: form.elements.password.value };
  if (authMode === "login" && form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try {
    await api(`/api/v1/auth/${authMode}`, { method: "POST", body: JSON.stringify(payload) });
    if (authMode === "register") {
      authMode = "login"; $('[data-auth-mode="login"]').click(); error.textContent = "Account created. Sign in to continue."; error.className = "notice";
    } else {
      showAuthenticated(await api("/api/v1/me")); form.reset();
    }
  } catch (reason) { error.textContent = reason.message; error.className = "notice error"; }
});

$("#sign-out").addEventListener("click", async () => { try { await api("/api/v1/auth/logout", { method: "POST" }); } finally { showSignedOut(); } });

$$('.tab').forEach((button) => button.addEventListener("click", () => {
  $$('.tab').forEach((item) => item.classList.toggle("active", item === button));
  $$('.page').forEach((page) => page.classList.toggle("active", page.id === `page-${button.dataset.page}`));
}));

$("#new-worker").addEventListener("click", () => $("#worker-create").classList.toggle("hidden"));
$("#worker-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try {
    const { worker } = await api("/api/v1/workers", { method: "POST", body: JSON.stringify({ label: form.elements.label.value }) });
    const secret = $("#worker-secret"); secret.textContent = `Username: ${worker.mining_username}\nToken (shown once): ${worker.token}`; secret.classList.remove("hidden"); form.reset(); refreshWorkers();
  } catch (reason) { const secret = $("#worker-secret"); secret.textContent = reason.message; secret.classList.remove("hidden"); }
});

$$('.payout-form').forEach((form) => form.addEventListener("submit", async (event) => {
  event.preventDefault(); const result = $(".setting-result", form);
  const payload = { destination: form.elements.destination.value, threshold_zat: Number(form.elements.threshold_zat.value), automatic: form.elements.automatic.checked, password: form.elements.password.value };
  if (form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try { const setting = await api(`/api/v1/settings/payouts/${form.dataset.asset}`, { method: "PUT", body: JSON.stringify(payload) }); result.textContent = setting.pending_destination ? `Change held until ${new Date(setting.pending_effective_at * 1000).toLocaleString()}.` : `Active destination: ${setting.active_destination}`; form.elements.destination.value = ""; form.elements.password.value = ""; form.elements.totp_code.value = ""; }
  catch (reason) { result.textContent = reason.message; }
}));

$("#totp-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const target = $("#totp-secret");
  const payload = { password: form.elements.password.value }; if (form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try { const data = await api("/api/v1/security/totp/begin", { method: "POST", body: JSON.stringify(payload) }); target.textContent = `Add this key to your authenticator:\n${data.secret_base32}`; target.classList.remove("hidden"); $("#totp-confirm").classList.remove("hidden"); }
  catch (reason) { target.textContent = reason.message; target.classList.remove("hidden"); }
});

$("#totp-confirm-button").addEventListener("click", async () => {
  const target = $("#totp-secret");
  try {
    await api("/api/v1/security/totp/confirm", { method: "POST", body: JSON.stringify({ code: $("#totp-confirm-code").value }) });
    target.textContent = "Authenticator enabled. Sign in again.";
    setTimeout(showSignedOut, 900);
  } catch (reason) { target.textContent = reason.message; }
});

api("/api/v1/me").then(showAuthenticated).catch(showSignedOut);
