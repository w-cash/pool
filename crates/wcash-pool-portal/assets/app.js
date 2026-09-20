"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const ATOMIC_UNITS = 100_000_000;
const MAX_PAYOUT_THRESHOLD_ZAT = 2_100_000_000_000_000n;
const AUTOMATIC_PAYOUT_ENABLED = { wec: true, zec: true };
const TLS_STRATUM_AVAILABLE = true;
const MINING_PASSWORD_IGNORED = false;
let authMode = "login";
let cachedWorkers = [];
let cachedTelemetry = null;
let authGeneration = 0;
let currentAccount = null;
let refreshTimer = null;
let refreshInFlight = false;
let cachedSettings = null;
let payoutHoldSecs = 172800;
let workerListAvailable = false;
let workersRequest = 0;
let settingsRequest = 0;
const STRATUM_ENDPOINTS = {
  tls: "stratum+ssl://testnet-mine.zecwec.com:3443",
  tcp: "stratum+tcp://testnet-mine.zecwec.com:3333",
};

const history = {
  rewards: { cursor: null, columns: 5, request: 0 },
  blocks: { cursor: null, columns: 5, request: 0 },
  payouts: { cursor: null, columns: 10, request: 0 },
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
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  const generation = authGeneration;
  try {
    const response = await fetch(path, { ...options, headers, credentials: "same-origin", signal: controller.signal });
    const contentType = response.headers.get("content-type") || "";
    const body = contentType.includes("json") ? await response.json() : null;
    if (!response.ok) {
      if (response.status === 401 && !options.method && currentAccount && currentGeneration(generation)) {
        showSignedOut();
        setText("#auth-error", "Your session expired. Sign in again.");
        $("#auth-error").className = "notice";
      }
      throw new Error(body?.message || `Request failed (${response.status})`);
    }
    return body;
  } catch (reason) {
    if (reason.name === "AbortError") throw new Error("Request timed out. Check the pool status before retrying.");
    throw reason;
  } finally {
    clearTimeout(timeout);
  }
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
  return `${whole}.${fraction} ${assetLabel(asset)}`;
}

function assetLabel(asset) {
  return asset === "wec" ? "TWC" : asset === "zec" ? "ZEC" : "Unknown asset";
}

// Parse decimal coin input before converting to the API's safe integer range.
// Floating-point multiplication can silently round eight-decimal amounts.
function parseCoinInput(value) {
  const match = /^(\d+)(?:\.(\d{1,8}))?$/.exec(String(value).trim());
  if (!match || match[1].length > 16) throw new Error("Enter a positive coin amount with up to 8 decimal places.");
  const atomic = BigInt(match[1]) * 100000000n + BigInt((match[2] || "").padEnd(8, "0"));
  if (atomic <= 0n || atomic > MAX_PAYOUT_THRESHOLD_ZAT) throw new Error("Enter a payout threshold above zero and no greater than 21,000,000 coins.");
  return Number(atomic);
}

function coinInputValue(value) {
  if (!Number.isSafeInteger(value) || value <= 0) return "";
  return `${Math.floor(value / ATOMIC_UNITS)}.${String(value % ATOMIC_UNITS).padStart(8, "0")}`;
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

function formatDuration(value) {
  if (!Number.isSafeInteger(value) || value <= 0) return "the configured hold";
  if (value % 86400 === 0) return `${value / 86400} day${value === 86400 ? "" : "s"}`;
  if (value % 3600 === 0) return `${value / 3600} hour${value === 3600 ? "" : "s"}`;
  if (value % 60 === 0) return `${value / 60} minute${value === 60 ? "" : "s"}`;
  return `${value} second${value === 1 ? "" : "s"}`;
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
  cachedSettings = null;
  workerListAvailable = false;
  workersRequest++;
  settingsRequest++;
  $$("form").forEach((form) => { setFormBusy(form, false); form.dataset.dirty = "false"; });
  const workerSecret = $("#worker-secret");
  workerSecret.textContent = "";
  workerSecret.classList.add("hidden");
  $("#worker-create").classList.add("hidden");
  $("#worker-form").reset();
  $("#worker-error").classList.add("hidden");
  $("#worker-error").textContent = "";
  $("#new-worker").setAttribute("aria-expanded", "false");
  $("#new-worker").disabled = false;

  $$(".payout-form").forEach((form) => {
    form.reset();
    $(".setting-result", form).textContent = "";
    $(".setting-summary", form).textContent = "Checking saved destination";
  });
  $("#totp-form").reset();
  $("#totp-secret").textContent = "";
  $("#totp-secret").classList.add("hidden");
  $("#totp-confirm").classList.add("hidden");
  $("#totp-confirm-code").value = "";
  $("#totp-confirm-button").disabled = false;
  $("#auth-form").reset();
  $("#auth-error").textContent = "";
  $("#auth-error").className = "notice error hidden";
  setText("#app-feedback", "");
  setText("#telemetry-state", "Checking activity");
  setText("#workers-state", "Checking workers");
  setText("#setup-addresses", "Checking");
  setText("#setup-workers", "Checking");
  setText("#totp-status", "Optional protection for your account");
  $("#setup-guide").classList.remove("hidden");
  updateAddressType();

  for (const asset of ["wec", "zec"]) {
    setText(`#${asset}-payout-status`, "Checking payout settings");
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
    state.request++;
    $(`#${kind}-more`).classList.add("hidden");
    setHistoryState(kind, "Sign in", "warning");
    renderTableMessage($(`#${kind}-body`), state.columns, "Sign in to view private history.");
  });
}

function showAuthenticated(account) {
  const generation = ++authGeneration;
  // Defensively erase any prior account's one-time credentials before
  // rendering the newly authenticated session.
  resetPrivateViews();
  currentAccount = account;
  $("#auth-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  $("#sign-out").classList.remove("hidden");
  setText("#account-name", account.username);
  setText("#totp-status", account.totp_enabled ? "Authenticator enabled" : "Optional protection for your account");
  $$(".totp-sensitive-field").forEach((field) => field.classList.toggle("hidden", !account.totp_enabled));
  navigate("overview", false);
  refreshAll(generation);
  Object.keys(history).forEach((kind) => refreshHistory(kind, false, generation));
}

function showSignedOut() {
  ++authGeneration;
  currentAccount = null;
  clearTimeout(refreshTimer);
  refreshInFlight = false;
  $("#auth-view").classList.remove("hidden");
  $("#app-view").classList.add("hidden");
  $("#sign-out").classList.add("hidden");
  setText("#account-name", "");
  resetPrivateViews();
}

function navigate(page, refresh = true) {
  if (!$("#page-" + page)) return;
  if (currentAccount && ((page !== "workers" && $("#worker-form").dataset.busy === "true") || (page !== "settings" && $("#totp-form").dataset.busy === "true"))) {
    setText("#app-feedback", "Wait for the one-time credential request to finish before changing pages.");
    return;
  }
  $$(".tab").forEach((button) => {
    const active = button.dataset.page === page;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  $$(".page").forEach((node) => node.classList.toggle("active", node.id === `page-${page}`));
  if (page !== "workers") clearWorkerSecret();
  if (page !== "settings") {
    $$('.payout-form input[type="password"], .payout-form input[name="totp_code"]').forEach((input) => { input.value = ""; });
    $("#totp-form").reset();
    $("#totp-secret").textContent = "";
    $("#totp-secret").classList.add("hidden");
    $("#totp-confirm").classList.add("hidden");
    $("#totp-confirm-code").value = "";
  }
  setText("#app-feedback", "");
  if (refresh && currentAccount) {
    if (history[page]) refreshHistory(page);
    else refreshAll();
  }
}

async function refreshAll(generation = authGeneration) {
  if (!currentAccount || refreshInFlight) return;
  refreshInFlight = true;
  clearTimeout(refreshTimer);
  $("#refresh-data").disabled = true;
  try {
    await Promise.all([refreshOverview(generation), refreshBalances(generation), refreshWorkers(generation), refreshPayoutSettings(generation)]);
  } finally {
    if (currentGeneration(generation)) {
      refreshInFlight = false;
      $("#refresh-data").disabled = false;
      if (currentAccount && !document.hidden) refreshTimer = setTimeout(() => refreshAll(), 15000);
    }
  }
}

function updateSetupGuide() {
  const configured = cachedSettings?.filter((setting) => setting.active_destination || setting.pending_destination).length;
  const workers = cachedWorkers.filter((worker) => !worker.revoked_at).length;
  setText("#setup-addresses", cachedSettings ? `${configured} of 2 added` : "Unavailable");
  setText("#setup-workers", workerListAvailable ? (workers ? `${workers} created` : "Add your first worker") : "Unavailable");
  $("#setup-guide").classList.toggle("hidden", configured === 2 && workerListAvailable && workers > 0);
}

async function refreshOverview(generation = authGeneration) {
  try {
    const [data, readiness] = await Promise.all([api("/api/v1/overview"), api("/readyz").then(() => true, () => false)]);
    if (!currentGeneration(generation)) return;
    setText("#pool-hashrate", data.hashrate_sol_s == null ? "Unavailable" : formatCount(data.hashrate_sol_s));
    setText("#pool-hashrate-note", data.hashrate_sol_s == null ? "No hashrate estimate yet" : "solutions / second");
    setText("#pool-active-workers", formatCount(data.active_workers));
    setText("#wcash-height", formatCount(data.wcash_height));
    setText("#zcash-height", formatCount(data.zcash_height));
    setText("#wec-fee", formatFeePolicy(data, "wec"));
    setText("#zec-fee", formatFeePolicy(data, "zec"));
    setText("#data-state", data.available ? (readiness ? "Pool services ready" : "Pool not ready") : "Pool data unavailable");
    $("#data-state").className = `status ${data.available && readiness ? "ok" : "warning"}`;
    setText("#connection-readiness", data.available && readiness ? "Pool services ready" : "Not ready · keep miner disconnected");
    $("#connection-readiness").className = `status ${data.available && readiness ? "ok" : "warning"}`;
    setText("#last-updated", data.updated_at ? `Pool data as of ${formatTime(data.updated_at)}` : "Pool update time unavailable");
    if (!data.available) {
      for (const id of ["pool-hashrate", "pool-active-workers", "wcash-height", "zcash-height"]) setText(`#${id}`, "Unavailable");
    }
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    setText("#data-state", reason.message);
    $("#data-state").className = "status warning";
    setText("#connection-readiness", "Status unavailable · check before connecting");
    $("#connection-readiness").className = "status warning";
    for (const id of ["pool-hashrate", "pool-active-workers", "wcash-height", "zcash-height"]) setText(`#${id}`, "Unavailable");
    setText("#last-updated", "Pool data unavailable");
  }
}

async function refreshBalances(generation = authGeneration) {
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
    for (const asset of ["wec", "zec"]) {
      setText(`#${asset}-balance`, "Unavailable");
      for (const field of ["immature", "payable", "pending"]) setText(`#${asset}-${field}`, "—");
    }
    setText("#app-feedback", reason.message);
  }
}

async function refreshWorkers(generation = authGeneration) {
  const body = $("#workers-body");
  const request = ++workersRequest;
  try {
    const [workerResponse, telemetry] = await Promise.all([
      api("/api/v1/workers"),
      api("/api/v1/telemetry"),
    ]);
    if (!currentGeneration(generation) || request !== workersRequest) return;
    if (!Array.isArray(workerResponse.workers)) throw new Error("Worker data is unavailable.");
    cachedWorkers = workerResponse.workers;
    workerListAvailable = true;
    cachedTelemetry = telemetry;
    renderWorkerTelemetry();
    renderAccountTelemetry();
    updateSetupGuide();
  } catch (reason) {
    if (!currentGeneration(generation) || request !== workersRequest) return;
    renderTableMessage(body, 9, reason.message, "empty error-text");
    workerListAvailable = false;
    cachedTelemetry = null;
    setText("#workers-state", "Worker data unavailable");
    setText("#telemetry-state", "Telemetry unavailable");
    updateSetupGuide();
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
    setText("#telemetry-state", "Telemetry unavailable");
    return;
  }
  setText("#miner-active-workers", formatCount(cachedTelemetry.active_workers));
  setText("#accepted-shares", formatCount(cachedTelemetry.accepted));
  setText("#stale-shares", formatCount(cachedTelemetry.stale));
  const rejected = Number.isSafeInteger(cachedTelemetry.invalid) && Number.isSafeInteger(cachedTelemetry.duplicate)
    ? cachedTelemetry.invalid + cachedTelemetry.duplicate
    : null;
  setText("#rejected-shares", formatCount(rejected));
  setText("#telemetry-state", cachedTelemetry.updated_at ? `Updated ${formatTime(cachedTelemetry.updated_at)}` : "Current service run");
}

function renderWorkerTelemetry() {
  const body = $("#workers-body");
  body.replaceChildren();
  if (!cachedWorkers.length) {
    renderTableMessage(body, 9, "No workers yet. Create one to connect an ASIC.");
    setText("#workers-state", "No workers created");
    return;
  }
  const byWorker = new Map((cachedTelemetry?.workers || []).map((item) => [item.worker_id, item]));
  cachedWorkers.forEach((worker) => {
    const telemetry = cachedTelemetry?.available ? byWorker.get(worker.id) : undefined;
    const row = body.insertRow();
    appendCell(row, worker.label);
    appendCell(row, worker.mining_username, "mono");
    const status = worker.revoked_at ? "Revoked" : !cachedTelemetry?.available ? "Unknown" : telemetry?.connections > 0 ? "Online" : "Offline";
    appendCell(row, status, status === "Online" ? "ok-text" : "");
    appendCell(row, formatCount(telemetry?.accepted ?? (cachedTelemetry?.available ? 0 : null)));
    appendCell(row, formatCount(telemetry?.stale ?? (cachedTelemetry?.available ? 0 : null)));
    appendCell(row, formatCount(telemetry?.invalid ?? (cachedTelemetry?.available ? 0 : null)));
    appendCell(row, formatCount(telemetry?.duplicate ?? (cachedTelemetry?.available ? 0 : null)));
    appendCell(row, formatTime(telemetry?.last_share_at));
    const action = row.insertCell();
    if (!worker.revoked_at) {
      const button = document.createElement("button");
      button.className = "button quiet";
      button.type = "button";
      button.textContent = "Revoke";
      button.addEventListener("click", async () => {
        if (!window.confirm(`Revoke mining access for ${worker.label}? Earned rewards are kept.`)) return;
        const generation = authGeneration;
        button.disabled = true;
        try {
          await api(`/api/v1/workers/${worker.id}`, { method: "DELETE" });
          if (currentGeneration(generation)) { clearWorkerSecret(); await refreshWorkers(generation); }
        } catch (reason) {
          if (!currentGeneration(generation)) return;
          setText("#app-feedback", reason.message);
          button.disabled = false;
        }
      });
      action.append(button);
    }
  });
  setText("#workers-state", cachedTelemetry?.available ? "Current service run · refreshes every 15 seconds" : "Worker list loaded · telemetry unavailable");
}

async function refreshPayoutSettings(generation = authGeneration) {
  const request = ++settingsRequest;
  try {
    const { settings, payout_change_hold_secs } = await api("/api/v1/settings/payouts");
    if (!currentGeneration(generation) || request !== settingsRequest) return;
    if (!Array.isArray(settings)) throw new Error("Payout settings are unavailable.");
    if (Number.isSafeInteger(payout_change_hold_secs) && payout_change_hold_secs > 0) payoutHoldSecs = payout_change_hold_secs;
    cachedSettings = settings.filter((setting) => ["wec", "zec"].includes(setting.asset));
    for (const asset of ["wec", "zec"]) renderPayoutSetting(asset, cachedSettings.find((setting) => setting.asset === asset));
    updateSetupGuide();
  } catch (reason) {
    if (!currentGeneration(generation) || request !== settingsRequest) return;
    cachedSettings = null;
    $$(".setting-summary").forEach((result) => { result.textContent = "Saved settings unavailable. Refresh before making a change."; });
    for (const asset of ["wec", "zec"]) setText(`#${asset}-payout-status`, "Payout settings unavailable");
    updateSetupGuide();
  }
}

function renderPayoutSetting(asset, setting) {
  const form = $(`.payout-form[data-asset="${asset}"]`);
  const summary = $(".setting-summary", form);
  summary.replaceChildren();
  const line = (value) => { const node = document.createElement("p"); node.textContent = value; summary.append(node); };
  if (!setting || (!setting.active_destination && !setting.pending_destination)) {
    line("No payout destination added.");
    setText(`#${asset}-payout-status`, "Payouts paused: add this chain’s destination. Earned rewards stay in its balance.");
    return;
  }
  if (setting.active_destination) {
    const receiver = setting.active_receiver === "transparent" ? "Transparent address" : "Shielded Unified Address";
    line(`${receiver}: ${setting.active_destination}`);
    line(`Current threshold: ${formatCoin(setting.threshold_zat, asset)} · ${AUTOMATIC_PAYOUT_ENABLED[asset] ? (setting.automatic ? "automatic" : "paused") : "payouts paused"}`);
  }
  if (setting.pending_destination) {
    line(`Pending destination: ${setting.pending_destination}`);
    line(`Safety hold until ${formatTime(setting.pending_effective_at)} (${formatDuration(payoutHoldSecs)}). ${AUTOMATIC_PAYOUT_ENABLED[asset] ? "Payouts remain paused until the change is active." : "Automatic payout execution remains paused after the hold."}`);
    line(`After the hold: ${formatCoin(setting.pending_threshold_zat, asset)} minimum · ${AUTOMATIC_PAYOUT_ENABLED[asset] ? (setting.pending_automatic ? "automatic" : "paused") : "payouts paused"}`);
    setText(`#${asset}-payout-status`, AUTOMATIC_PAYOUT_ENABLED[asset]
      ? `Payouts on hold until ${formatTime(setting.pending_effective_at)}. Rewards continue accumulating.`
      : "Automatic payouts are paused. Rewards continue accumulating.");
  } else {
    setText(`#${asset}-payout-status`, !AUTOMATIC_PAYOUT_ENABLED[asset]
      ? "Automatic payouts are paused. Earned rewards remain in this balance."
      : setting.automatic ? `Automatic payouts after maturity and ${formatCoin(setting.threshold_zat, asset)} threshold.` : "Automatic payouts paused. Earned rewards remain in this balance.");
  }
  // Never refill a masked destination or replace an in-progress edit with a poll.
  if (form.dataset.dirty !== "true") {
    form.elements.threshold_coin.value = coinInputValue(setting.pending_threshold_zat ?? setting.threshold_zat);
    form.elements.automatic.checked = AUTOMATIC_PAYOUT_ENABLED[asset]
      && (setting.pending_automatic ?? setting.automatic);
    form.elements.automatic.disabled = !AUTOMATIC_PAYOUT_ENABLED[asset];
    if (asset === "zec" && !setting.pending_destination) {
      form.elements.address_type.value = setting.active_receiver === "transparent" ? "transparent" : "shielded";
      updateAddressType();
    }
  }
}

function updateAddressType() {
  const transparent = $("#zec-address-type").value === "transparent";
  setText("#zec-address-help", transparent
    ? "Use a Zcash Testnet transparent address. Its payout amount and destination are public on the chain."
    : "Use a Zcash Testnet Unified Address with a supported shielded receiver.");
}

function clearWorkerSecret() {
  const workerSecret = $("#worker-secret");
  $$("input", workerSecret).forEach((input) => { input.value = ""; });
  workerSecret.textContent = "";
  workerSecret.classList.add("hidden");
  $("#new-worker").disabled = false;
  $("#worker-form button").disabled = false;
}

async function copyInput(input) {
  const generation = authGeneration;
  try {
    if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText(input.value);
    if (currentGeneration(generation)) setText("#app-feedback", "Copied.");
  } catch (_) {
    if (!currentGeneration(generation) || !input.isConnected) return;
    input.focus(); input.select();
    setText("#app-feedback", "Value selected. Press Ctrl+C or ⌘C to copy.");
  }
}

function renderWorkerSecret(worker) {
  const target = $("#worker-secret");
  target.replaceChildren();
  const title = document.createElement("h3");
  title.textContent = MINING_PASSWORD_IGNORED ? "Worker ready" : "Save your worker token now";
  const note = document.createElement("p");
  note.className = "fineprint";
  note.textContent = MINING_PASSWORD_IGNORED ? "Copy the exact mining username. Set the ASIC password to x." : "Shown once. Copy these into the ASIC’s username and password fields. Leaving this page clears the token.";
  target.append(title, note);
  for (const [id, label, value] of [["issued-worker-username", "Mining username", worker.mining_username], ["issued-worker-token", MINING_PASSWORD_IGNORED ? "Password · ignored" : "Miner password · mining-only token", MINING_PASSWORD_IGNORED ? "x" : worker.token]]) {
    const field = document.createElement("div"); field.className = "secret-field";
    const heading = document.createElement("label"); heading.htmlFor = id; heading.textContent = label;
    const row = document.createElement("div"); row.className = "copy-row";
    const input = document.createElement("input"); input.id = id; input.readOnly = true; input.value = value;
    const copy = document.createElement("button"); copy.type = "button"; copy.className = "button secondary"; copy.textContent = "Copy"; copy.setAttribute("aria-label", `Copy ${label}`);
    copy.addEventListener("click", () => copyInput(input));
    row.append(input, copy); field.append(heading, row); target.append(field);
  }
  const actions = document.createElement("div"); actions.className = "secret-actions";
  const dismiss = document.createElement("button"); dismiss.type = "button"; dismiss.className = "button secondary"; dismiss.textContent = MINING_PASSWORD_IGNORED ? "Done" : "I saved it · hide token";
  dismiss.addEventListener("click", () => { clearWorkerSecret(); $("#worker-create").classList.add("hidden"); $("#new-worker").setAttribute("aria-expanded", "false"); });
  actions.append(dismiss); target.append(actions); target.classList.remove("hidden");
  $("#new-worker").disabled = true;
  $("#worker-form button").disabled = true;
}

function setFormBusy(form, busy) {
  form.dataset.busy = String(busy);
  form.setAttribute("aria-busy", String(busy));
  $$('button[type="submit"]', form).forEach((button) => { button.disabled = busy; });
}

function renderReward(row, item) {
  appendCell(row, assetLabel(item.asset));
  appendCell(row, formatCount(item.block_height));
  appendCell(row, item.block_hash || "—", "mono hash");
  appendCell(row, formatCoin(item.amount_zat, item.asset || ""));
  appendStateCell(row, item.state);
}

function renderBlock(row, item) {
  appendCell(row, assetLabel(item.asset));
  appendCell(row, formatCount(item.height));
  appendCell(row, item.block_hash || "—", "mono hash");
  appendCell(row, formatCoin(item.reward_zat, item.asset || ""));
  appendStateCell(row, item.state);
}

function renderPayout(row, item) {
  appendCell(row, assetLabel(item.asset));
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
  const request = ++state.request;
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
    if (!currentGeneration(generation) || request !== state.request) return;
    if (!Array.isArray(page.items)) throw new Error("History data is unavailable.");
    if (!append) body.replaceChildren();
    const renderer = kind === "rewards" ? renderReward : kind === "blocks" ? renderBlock : renderPayout;
    page.items.forEach((item) => renderer(body.insertRow(), item));
    if (!body.rows.length) renderTableMessage(body, state.columns, `No ${kind} recorded for this account.`);
    state.cursor = Number.isSafeInteger(page.next_before) ? page.next_before : null;
    more.classList.toggle("hidden", state.cursor == null);
    setHistoryState(kind, page.items.length ? "Account data" : "No records", "ok");
  } catch (reason) {
    if (!currentGeneration(generation) || request !== state.request) return;
    if (!append || !body.rows.length) renderTableMessage(body, state.columns, reason.message, "empty error-text");
    setHistoryState(kind, "Unavailable", "warning");
    more.classList.add("hidden");
  } finally {
    if (currentGeneration(generation) && request === state.request) more.disabled = false;
  }
}

$$('[data-auth-mode]').forEach((button) => button.addEventListener("click", () => {
  if ($("#auth-form").dataset.busy === "true") return;
  authMode = button.dataset.authMode;
  $$('[data-auth-mode]').forEach((item) => { item.classList.toggle("active", item === button); item.setAttribute("aria-pressed", String(item === button)); });
  setText("#auth-submit", authMode === "login" ? "Sign in" : "Create account");
  $("#totp-login-field").classList.toggle("hidden", authMode !== "login");
  $("#auth-form").elements.password.autocomplete = authMode === "login" ? "current-password" : "new-password";
  $("#auth-form").elements.totp_code.disabled = authMode !== "login";
  $("#auth-error").classList.add("hidden");
}));

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (form.dataset.busy === "true") return;
  setFormBusy(form, true);
  const error = $("#auth-error");
  const mode = authMode;
  const generation = ++authGeneration;
  error.classList.add("hidden");
  const payload = { username: form.elements.username.value, password: form.elements.password.value };
  if (mode === "login" && form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try {
    await api(`/api/v1/auth/${mode}`, { method: "POST", body: JSON.stringify(payload) });
    if (!currentGeneration(generation)) return;
    if (mode === "register") {
      authMode = "login";
      setFormBusy(form, false);
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
  } finally {
    if (currentGeneration(generation)) {
      form.elements.password.value = "";
      form.elements.totp_code.value = "";
      setFormBusy(form, false);
    }
  }
});

$("#sign-out").addEventListener("click", async () => {
  const request = api("/api/v1/auth/logout", { method: "POST" });
  showSignedOut();
  try { await request; } catch (_) {
    if (!currentAccount) {
      setText("#auth-error", "Private data cleared from this page, but sign-out could not be confirmed. Retry Sign out before leaving this device.");
      $("#auth-error").className = "notice error";
      $("#sign-out").classList.remove("hidden");
    }
  }
});

$$('.tab').forEach((button) => button.addEventListener("click", () => navigate(button.dataset.page)));
$$('[data-go]').forEach((button) => button.addEventListener("click", () => navigate(button.dataset.go)));
$(".brand").addEventListener("click", () => { if (currentAccount) navigate("overview"); });
$("#refresh-data").addEventListener("click", () => refreshAll());
$("#stratum-transport").addEventListener("change", () => {
  const transport = $("#stratum-transport").value;
  $("#stratum-url").value = STRATUM_ENDPOINTS[transport];
  setText("#transport-help", MINING_PASSWORD_IGNORED ? "Use the exact mining username shown below. Set the ASIC password to x." : transport === "tls" ? "Use TLS when your ASIC firmware supports it." : TLS_STRATUM_AVAILABLE
    ? "TCP is unencrypted. Use it only when your ASIC cannot use TLS. Enter the mining-only token, never your account password."
    : "TCP is unencrypted. Enter the mining-only token, never your account password.");
});
$$('[data-copy]').forEach((button) => button.addEventListener("click", () => copyInput(document.getElementById(button.dataset.copy))));
$("#zec-address-type").addEventListener("change", updateAddressType);
document.addEventListener("visibilitychange", () => { clearTimeout(refreshTimer); if (!document.hidden && currentAccount) refreshAll(); });

Object.keys(history).forEach((kind) => {
  $(`#${kind}-more`).addEventListener("click", () => refreshHistory(kind, true));
});

$("#new-worker").addEventListener("click", () => {
  const hidden = $("#worker-create").classList.toggle("hidden");
  $("#new-worker").setAttribute("aria-expanded", String(!hidden));
  if (!hidden) $("#worker-label").focus();
});
$("#worker-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (form.dataset.busy === "true" || !$("#worker-secret").classList.contains("hidden")) return;
  setFormBusy(form, true);
  const error = $("#worker-error");
  error.classList.add("hidden");
  const generation = authGeneration;
  try {
    const { worker } = await api("/api/v1/workers", { method: "POST", body: JSON.stringify({ label: form.elements.label.value }) });
    if (!currentGeneration(generation)) return;
    renderWorkerSecret(worker);
    form.reset();
    await refreshWorkers(generation);
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    error.textContent = reason.message;
    error.classList.remove("hidden");
  } finally {
    if (currentGeneration(generation)) {
      setFormBusy(form, false);
      $("#worker-form button").disabled = !$("#worker-secret").classList.contains("hidden");
    }
  }
});

$$('.payout-form').forEach((form) => form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (form.dataset.busy === "true") return;
  const result = $(".setting-result", form);
  const generation = authGeneration;
  setFormBusy(form, true);
  try {
    const payload = {
      destination: form.elements.destination.value,
      threshold_zat: parseCoinInput(form.elements.threshold_coin.value),
      automatic: AUTOMATIC_PAYOUT_ENABLED[form.dataset.asset] && form.elements.automatic.checked,
      password: form.elements.password.value,
    };
    if (form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
    const setting = await api(`/api/v1/settings/payouts/${form.dataset.asset}`, { method: "PUT", body: JSON.stringify(payload) });
    if (!currentGeneration(generation)) return;
    result.textContent = setting.pending_destination
      ? `Saved. Payouts are held until ${formatTime(setting.pending_effective_at)}. No payout is created during the hold.`
      : "Payout setting saved.";
    form.elements.destination.value = "";
    form.elements.password.value = "";
    form.elements.totp_code.value = "";
    form.dataset.dirty = "false";
    renderPayoutSetting(form.dataset.asset, setting);
    await refreshPayoutSettings(generation);
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    result.textContent = reason.message;
  } finally {
    if (currentGeneration(generation)) {
      form.elements.password.value = "";
      form.elements.totp_code.value = "";
      setFormBusy(form, false);
    }
  }
}));

$$('.payout-form').forEach((form) => {
  form.addEventListener("input", () => { form.dataset.dirty = "true"; });
  form.addEventListener("change", () => { form.dataset.dirty = "true"; });
});

$("#totp-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (form.dataset.busy === "true") return;
  setFormBusy(form, true);
  const target = $("#totp-secret");
  const generation = authGeneration;
  const payload = { password: form.elements.password.value };
  if (form.elements.totp_code.value) payload.totp_code = form.elements.totp_code.value;
  try {
    const data = await api("/api/v1/security/totp/begin", { method: "POST", body: JSON.stringify(payload) });
    if (!currentGeneration(generation)) return;
    target.textContent = `Add this setup key to your authenticator: ${data.secret_base32}. Confirm before ${formatTime(data.expires_at)}.`;
    target.classList.remove("hidden");
    $("#totp-confirm").classList.remove("hidden");
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    target.textContent = reason.message;
    target.classList.remove("hidden");
  } finally {
    if (currentGeneration(generation)) {
      form.elements.password.value = "";
      form.elements.totp_code.value = "";
      setFormBusy(form, false);
    }
  }
});

$("#totp-confirm-button").addEventListener("click", async () => {
  const target = $("#totp-secret");
  const generation = authGeneration;
  if (!/^[0-9]{6}$/.test($("#totp-confirm-code").value)) { target.textContent = "Enter the six-digit authenticator code."; return; }
  $("#totp-confirm-button").disabled = true;
  try {
    await api("/api/v1/security/totp/confirm", { method: "POST", body: JSON.stringify({ code: $("#totp-confirm-code").value }) });
    if (!currentGeneration(generation)) return;
    showSignedOut();
    setText("#auth-error", "Authenticator enabled. Sign in again with your code.");
    $("#auth-error").className = "notice";
  } catch (reason) {
    if (!currentGeneration(generation)) return;
    target.textContent = reason.message;
  } finally {
    if (currentGeneration(generation)) {
      $("#totp-confirm-code").value = "";
      $("#totp-confirm-button").disabled = false;
    }
  }
});

function restoreSession() {
  const generation = authGeneration;
  api("/api/v1/me")
    .then((account) => { if (currentGeneration(generation)) showAuthenticated(account); })
    .catch(() => { if (currentGeneration(generation)) showSignedOut(); });
}

// A browser back/forward cache must not preserve a revealed worker or TOTP key.
window.addEventListener("pagehide", showSignedOut);
window.addEventListener("pageshow", (event) => { if (event.persisted) restoreSession(); });
restoreSession();
