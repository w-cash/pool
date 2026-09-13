"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const ATOMIC_UNITS = 100_000_000;
let authMode = "login";
let cachedWorkers = [];
let cachedTelemetry = null;
let authGeneration = 0;

const history = {
  rewards: { cursor: null, columns: 5 },
  blocks: { cursor: null, columns: 5 },
  payouts: { cursor: null, columns: 10 },
};

function csrfToken() {
  const row = document.cookie
    .split(";")
    .map((value) => value.trim())
    .find((value) => value.startsWith("__Host-zecwec_csrf="));
  return row ? row.split("=").slice(1).join("=") : "";
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("content-type", "application/json");
  if (options.method && !["GET", "HEAD"].includes(options.method)) {
    headers.set("x-csrf-token", csrfToken());
  }
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("json") ? await response.json() : null;
  if (!response.ok) throw new Error(body?.message || `Request failed (${response.status})`);
  return body;
}

function setText(selector, value) {
  const node = $(selector);
  if (node) node.textContent = value;
}

function formatCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : "—";
}

function formatCoin(value, asset) {
  if (!Number.isSafeInteger(value) || value < 0) return "Unavailable";
  const whole = Math.floor(value / ATOMIC_UNITS).toLocaleString();
  const fraction = String(value % ATOMIC_UNITS).padStart(8, "0");
  return `${whole}.${fraction} ${String(asset).toUpperCase()}`;
}

function formatOptionalCoin(value, asset) {
  return value == null ? "—" : formatCoin(value, asset);
}

function formatBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 ? `${(value / 100).toFixed(2)}%` : "—";
}

function formatFeePolicy(data, asset) {
  const prefix = asset === "wec" ? "wec" : "zec";
  const poolFee = data[`${prefix}_fee_bps`];
  const maximumFee = data[`${prefix}_maximum_network_fee_zat`];
  const maximumRate = data[`${prefix}_maximum_network_fee_bps`];
  if (![poolFee, maximumFee, maximumRate].every((value) => Number.isSafeInteger(value) && value >= 0)) {
    return "Fee policy unavailable";
  }
  const revision = data.fee_policy_revision ? ` · policy v${data.fee_policy_revision}` : "";
  return `Service fee ${formatBasisPoints(poolFee)} · payout transaction fee paid by miners; reserve capped at the lower of ${formatCoin(maximumFee, asset)}, ${formatBasisPoints(maximumRate)} of the gross batch, and the nonzero-output bound; unused reserve is returned${revision}`;
}

function formatTime(value) {
  if (!Number.isSafeInteger(value) || value <= 0) return "—";
  return new Date(value * 1000).toLocaleString();
}

function formatState(value) {
  if (typeof value !== "string" || !value) return "Unknown";
  return value.replaceAll("_", " ").replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
}

function appendCell(row, value, className = "") {
  const cell = row.insertCell();
  cell.textContent = String(value);
  if (className) cell.className = className;
  return cell;
}

function appendStateCell(row, value) {
  const cell = row.insertCell();
  const badge = document.createElement("span");
  badge.className = "lifecycle";
  badge.textContent = formatState(value);
  cell.append(badge);
}

function renderTableMessage(body, columns, message, className = "empty") {
  body.replaceChildren();
  const row = body.insertRow();
  const cell = row.insertCell();
  cell.colSpan = columns;
  cell.className = className;
  cell.textContent = message;
}

function setHistoryState(kind, label, stateClass) {
  const target = $(`#${kind}-state`);
  target.textContent = label;
  target.className = `status ${stateClass}`;
}

function currentGeneration(generation) {
  return generation === authGeneration;
}

function resetPrivateViews() {
  cachedWorkers = [];
  cachedTelemetry = null;
  const workerSecret = $("#worker-secret");
  workerSecret.textContent = "";
  workerSecret.classList.add("hidden");
  $("#worker-create").classList.add("hidden");
  $("#worker-form").reset();

  $$(".payout-form").forEach((form) => {
    form.reset();
    $(".setting-result", form).textContent = "";
  });
  $("#totp-form").reset();
  $("#totp-secret").textContent = "";
  $("#totp-secret").classList.add("hidden");
  $("#totp-confirm").classList.add("hidden");
  $("#totp-confirm-code").value = "";
  $("#auth-form").reset();
  $("#auth-error").textContent = "";
  $("#auth-error").className = "notice error hidden";

  for (const asset of ["wec", "zec"]) {
    for (const field of ["balance", "immature", "payable", "pending"]) {
      setText(`#${asset}-${field}`, "—");
    }
  }
  for (const id of ["miner-active-workers", "accepted-shares", "stale-shares", "rejected-shares"]) {
    setText(`#${id}`, "—");
  }
  renderTableMessage($("#workers-body"), 9, "Sign in to view private workers.");
  Object.entries(history).forEach(([kind, state]) => {
    state.cursor = null;
    $(`#${kind}-more`).classList.add("hidden");
    renderTableMessage($(`#${kind}-body`), state.columns, "Sign in to view private history.");
  });
}

function showAuthenticated(account) {
  const generation = ++authGeneration;
  // Defensively erase any prior account's one-time credentials before
  // rendering the newly authenticated session.
  resetPrivateViews();
  $("#auth-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  $("#sign-out").classList.remove("hidden");
  setText("#account-name", account.username);
  refreshOverview(generation);
  refreshBalances(generation);
  refreshWorkers(generation);
  refreshPayoutSettings(generation);
  Object.keys(history).forEach((kind) => refreshHistory(kind, false, generation));
}

function showSignedOut() {
  ++authGeneration;
  $("#auth-view").classList.remove("hidden");
  $("#app-view").classList.add("hidden");
  $("#sign-out").classList.add("hidden");
  setText("#account-name", "");
  resetPrivateViews();
}

async function refreshOverview(generation = authGeneration) {
  try {
    const data = await api("/api/v1/overview");
    if (!currentGeneration(generation)) return;
    setText("#pool-hashrate", data.hashrate_sol_s == null ? "Not calibrated" : formatCount(data.hashrate_sol_s));
    setText("#pool-hashrate-note", data.hashrate_sol_s == null ? "no verified sol/s projection" : "solutions / second");
    setText("#pool-active-workers", formatCount(data.active_workers));
    setText("#wcash-height", formatCount(data.wcash_height));
    setText("#zcash-height", formatCount(data.zcash_height));
    setText("#wec-fee", formatFeePolicy(data, "wec"));
    setText("#zec-fee", formatFeePolicy(data, "zec"));
    setText("#data-state", data.available ? "Pool projection live" : "Pool projection offline");
    $("#data-state").className = `status ${data.available ? "ok" : "warning"}`;
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    setText("#data-state", reason.message);
    $("#data-state").className = "status warning";
  }
}

async function refreshBalances(generation = authGeneration) {
  for (const asset of ["wec", "zec"]) {
    setText(`#${asset}-balance`, "Loading");
    setText(`#${asset}-immature`, "—");
    setText(`#${asset}-payable`, "—");
    setText(`#${asset}-pending`, "—");
  }
  try {
    const { balances } = await api("/api/v1/balances");
    if (!currentGeneration(generation)) return;
    if (!Array.isArray(balances)) throw new Error("Balance data is unavailable.");
    for (const asset of ["wec", "zec"]) {
      const balance = balances.find((item) => item.asset === asset);
      if (!balance) throw new Error("Balance data is incomplete.");
      setText(`#${asset}-balance`, formatCoin(balance.total_zat, asset));
      setText(`#${asset}-immature`, formatCoin(balance.immature_zat, asset));
      setText(`#${asset}-payable`, formatCoin(balance.payable_zat, asset));
      setText(`#${asset}-pending`, formatCoin(balance.pending_zat, asset));
    }
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    for (const asset of ["wec", "zec"]) setText(`#${asset}-balance`, reason.message);
  }
}

async function refreshWorkers(generation = authGeneration) {
  const body = $("#workers-body");
  renderTableMessage(body, 9, "Loading workers…");
  try {
    const [workerResponse, telemetry] = await Promise.all([
      api("/api/v1/workers"),
      api("/api/v1/telemetry"),
    ]);
    if (!currentGeneration(generation)) return;
    cachedWorkers = Array.isArray(workerResponse.workers) ? workerResponse.workers : [];
    cachedTelemetry = telemetry;
    renderWorkerTelemetry();
    renderAccountTelemetry();
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    renderTableMessage(body, 9, reason.message, "empty error-text");
    for (const id of ["miner-active-workers", "accepted-shares", "stale-shares", "rejected-shares"]) {
      setText(`#${id}`, "Unavailable");
    }
  }
}

function renderAccountTelemetry() {
  if (!cachedTelemetry?.available) {
    for (const id of ["miner-active-workers", "accepted-shares", "stale-shares", "rejected-shares"]) {
      setText(`#${id}`, "Unavailable");
    }
    return;
  }
  setText("#miner-active-workers", formatCount(cachedTelemetry.active_workers));
  setText("#accepted-shares", formatCount(cachedTelemetry.accepted));
  setText("#stale-shares", formatCount(cachedTelemetry.stale));
  const rejected = Number.isSafeInteger(cachedTelemetry.invalid) && Number.isSafeInteger(cachedTelemetry.duplicate)
    ? cachedTelemetry.invalid + cachedTelemetry.duplicate
    : null;
  setText("#rejected-shares", formatCount(rejected));
}

function renderWorkerTelemetry() {
  const body = $("#workers-body");
  body.replaceChildren();
  if (!cachedWorkers.length) {
    renderTableMessage(body, 9, "No workers yet. Create one to connect an ASIC.");
    return;
  }
  const byWorker = new Map((cachedTelemetry?.workers || []).map((item) => [item.worker_id, item]));
  cachedWorkers.forEach((worker) => {
    const telemetry = byWorker.get(worker.id);
    const row = body.insertRow();
    appendCell(row, worker.label);
    appendCell(row, worker.mining_username, "mono");
    const status = worker.revoked_at ? "Revoked" : telemetry?.connections > 0 ? "Online" : "Offline";
    appendCell(row, status, status === "Online" ? "ok-text" : "");
    appendCell(row, formatCount(telemetry?.accepted ?? 0));
    appendCell(row, formatCount(telemetry?.stale ?? 0));
    appendCell(row, formatCount(telemetry?.invalid ?? 0));
    appendCell(row, formatCount(telemetry?.duplicate ?? 0));
    appendCell(row, formatTime(telemetry?.last_share_at));
    const action = row.insertCell();
    if (!worker.revoked_at) {
      const button = document.createElement("button");
      button.className = "button quiet";
      button.type = "button";
      button.textContent = "Revoke";
      button.addEventListener("click", async () => {
        const generation = authGeneration;
        try {
          await api(`/api/v1/workers/${worker.id}`, { method: "DELETE" });
          if (currentGeneration(generation)) await refreshWorkers(generation);
        } catch (reason) {
          if (!currentGeneration(generation)) return;
          renderTableMessage(body, 9, reason.message, "empty error-text");
        }
      });
      action.append(button);
    }
  });
}

async function refreshPayoutSettings(generation = authGeneration) {
  try {
    const { settings } = await api("/api/v1/settings/payouts");
    if (!currentGeneration(generation)) return;
    settings.forEach((setting) => {
      const form = $(`.payout-form[data-asset="${setting.asset}"]`);
      if (!form) return;
      const result = $(".setting-result", form);
      const parts = [];
      if (setting.active_destination) {
        const mode = setting.automatic ? "automatic" : "paused";
        parts.push(`Active: ${setting.active_destination} · threshold ${formatCoin(setting.threshold_zat, setting.asset)} · ${mode} · revision ${setting.revision}`);
      }
      if (setting.pending_destination) {
        const pendingMode = setting.pending_automatic ? "automatic" : "paused";
        parts.push(`Pending until ${formatTime(setting.pending_effective_at)}: ${setting.pending_destination} · threshold ${formatCoin(setting.pending_threshold_zat, setting.asset)} · ${pendingMode} · revision ${setting.pending_revision}`);
      }
      result.textContent = parts.length ? parts.join(" · ") : "No payout destination configured.";
      if (setting.threshold_zat) form.elements.threshold_zat.value = setting.threshold_zat;
      form.elements.automatic.checked = setting.automatic;
    });
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    $$(".setting-result").forEach((result) => { result.textContent = reason.message; });
  }
}

function renderReward(row, item) {
  appendCell(row, String(item.asset || "").toUpperCase());
  appendCell(row, formatCount(item.block_height));
  appendCell(row, item.block_hash || "—", "mono hash");
  appendCell(row, formatCoin(item.amount_zat, item.asset || ""));
  appendStateCell(row, item.state);
}

function renderBlock(row, item) {
  appendCell(row, String(item.asset || "").toUpperCase());
  appendCell(row, formatCount(item.height));
  appendCell(row, item.block_hash || "—", "mono hash");
  appendCell(row, formatCoin(item.reward_zat, item.asset || ""));
  appendStateCell(row, item.state);
}

function renderPayout(row, item) {
  appendCell(row, String(item.asset || "").toUpperCase());
  appendCell(row, formatCoin(item.gross_amount_zat, item.asset || ""));
  appendCell(row, formatOptionalCoin(item.reserved_network_fee_zat, item.asset || ""));
  appendCell(row, formatOptionalCoin(item.actual_network_fee_zat, item.asset || ""));
  appendCell(row, formatOptionalCoin(item.refunded_network_fee_zat, item.asset || ""));
  appendCell(row, formatCoin(item.amount_zat, item.asset || ""));
  appendStateCell(row, item.state);
  appendCell(row, item.batch_id || "—", "mono hash");
  appendCell(row, item.transaction_id || "Not broadcast", "mono hash");
  appendCell(row, item.confirmation_height == null ? "—" : formatCount(item.confirmation_height));
}

async function refreshHistory(kind, append = false, generation = authGeneration) {
  const state = history[kind];
  const body = $(`#${kind}-body`);
  const more = $(`#${kind}-more`);
  if (!append) {
    state.cursor = null;
    renderTableMessage(body, state.columns, `Loading ${kind}…`);
  }
  setHistoryState(kind, "Loading", "warning");
  more.disabled = true;
  try {
    const query = state.cursor == null ? "?limit=50" : `?limit=50&before=${state.cursor}`;
    const page = await api(`/api/v1/${kind}${query}`);
    if (!currentGeneration(generation)) return;
    if (!Array.isArray(page.items)) throw new Error("History data is unavailable.");
    if (!append) body.replaceChildren();
    const renderer = kind === "rewards" ? renderReward : kind === "blocks" ? renderBlock : renderPayout;
    page.items.forEach((item) => renderer(body.insertRow(), item));
    if (!body.rows.length) renderTableMessage(body, state.columns, `No ${kind} recorded for this account.`);
    state.cursor = Number.isSafeInteger(page.next_before) ? page.next_before : null;
    more.classList.toggle("hidden", state.cursor == null);
    setHistoryState(kind, page.items.length ? "Account data" : "No records", "ok");
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    if (!append || !body.rows.length) renderTableMessage(body, state.columns, reason.message, "empty error-text");
    setHistoryState(kind, "Unavailable", "warning");
    more.classList.add("hidden");
  } finally {
    if (currentGeneration(generation)) more.disabled = false;
  }
}

$$('[data-auth-mode]').forEach((button) => button.addEventListener("click", () => {
  authMode = button.dataset.authMode;
  $$('[data-auth-mode]').forEach((item) => item.classList.toggle("active", item === button));
  setText("#auth-submit", authMode === "login" ? "Sign in" : "Create account");
  $("#totp-login-field").classList.toggle("hidden", authMode !== "login");
  $("#auth-form").elements.password.autocomplete = authMode === "login" ? "current-password" : "new-password";
}));

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const error = $("#auth-error");
  const generation = ++authGeneration;
  error.classList.add("hidden");
  const payload = { username: form.elements.username.value, password: form.elements.password.value };
  if (authMode === "login" && form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try {
    await api(`/api/v1/auth/${authMode}`, { method: "POST", body: JSON.stringify(payload) });
    if (!currentGeneration(generation)) return;
    if (authMode === "register") {
      authMode = "login";
      $('[data-auth-mode="login"]').click();
      error.textContent = "Account created. Sign in to continue.";
      error.className = "notice";
    } else {
      const account = await api("/api/v1/me");
      if (!currentGeneration(generation)) return;
      showAuthenticated(account);
      form.reset();
    }
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    error.textContent = reason.message;
    error.className = "notice error";
  }
});

$("#sign-out").addEventListener("click", async () => {
  const request = api("/api/v1/auth/logout", { method: "POST" });
  showSignedOut();
  try { await request; } catch (_) { /* local secrets are already cleared */ }
});

$$('.tab').forEach((button) => button.addEventListener("click", () => {
  $$('.tab').forEach((item) => item.classList.toggle("active", item === button));
  $$('.page').forEach((page) => page.classList.toggle("active", page.id === `page-${button.dataset.page}`));
}));

Object.keys(history).forEach((kind) => {
  $(`#${kind}-more`).addEventListener("click", () => refreshHistory(kind, true));
});

$("#new-worker").addEventListener("click", () => $("#worker-create").classList.toggle("hidden"));
$("#worker-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const secret = $("#worker-secret");
  const generation = authGeneration;
  try {
    const { worker } = await api("/api/v1/workers", { method: "POST", body: JSON.stringify({ label: form.elements.label.value }) });
    if (!currentGeneration(generation)) return;
    secret.textContent = `Username: ${worker.mining_username}\nToken (shown once): ${worker.token}`;
    secret.classList.remove("hidden");
    form.reset();
    await refreshWorkers(generation);
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    secret.textContent = reason.message;
    secret.classList.remove("hidden");
  }
});

$$('.payout-form').forEach((form) => form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = $(".setting-result", form);
  const generation = authGeneration;
  const payload = {
    destination: form.elements.destination.value,
    threshold_zat: Number(form.elements.threshold_zat.value),
    automatic: form.elements.automatic.checked,
    password: form.elements.password.value,
  };
  if (form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try {
    const setting = await api(`/api/v1/settings/payouts/${form.dataset.asset}`, { method: "PUT", body: JSON.stringify(payload) });
    if (!currentGeneration(generation)) return;
    result.textContent = setting.pending_destination
      ? `Pending until ${formatTime(setting.pending_effective_at)}: ${setting.pending_destination} · threshold ${formatCoin(setting.pending_threshold_zat, setting.asset)} · ${setting.pending_automatic ? "automatic" : "paused"} · revision ${setting.pending_revision}. No payout is created during the hold.`
      : `Active: ${setting.active_destination} · threshold ${formatCoin(setting.threshold_zat, setting.asset)} · ${setting.automatic ? "automatic" : "paused"} · revision ${setting.revision}.`;
    form.elements.destination.value = "";
    form.elements.password.value = "";
    form.elements.totp_code.value = "";
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    result.textContent = reason.message;
  }
}));

$("#totp-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const target = $("#totp-secret");
  const generation = authGeneration;
  const payload = { password: form.elements.password.value };
  if (form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try {
    const data = await api("/api/v1/security/totp/begin", { method: "POST", body: JSON.stringify(payload) });
    if (!currentGeneration(generation)) return;
    target.textContent = `Add this key to your authenticator:\n${data.secret_base32}`;
    target.classList.remove("hidden");
    $("#totp-confirm").classList.remove("hidden");
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    target.textContent = reason.message;
    target.classList.remove("hidden");
  }
});

$("#totp-confirm-button").addEventListener("click", async () => {
  const target = $("#totp-secret");
  const generation = authGeneration;
  try {
    await api("/api/v1/security/totp/confirm", { method: "POST", body: JSON.stringify({ code: $("#totp-confirm-code").value }) });
    if (!currentGeneration(generation)) return;
    target.textContent = "Authenticator enabled. Sign in again.";
    setTimeout(() => {
      if (currentGeneration(generation)) showSignedOut();
    }, 900);
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    target.textContent = reason.message;
  }
});

const initialGeneration = authGeneration;
api("/api/v1/me")
  .then((account) => {
    if (currentGeneration(initialGeneration)) showAuthenticated(account);
  })
  .catch(() => {
    if (currentGeneration(initialGeneration)) showSignedOut();
  });
