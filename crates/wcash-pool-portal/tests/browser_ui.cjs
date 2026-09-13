/* Browser regression checks for the embedded portal assets.
 * Run with an externally provided Playwright installation:
 * NODE_PATH=<node_modules> node --test crates/wcash-pool-portal/tests/browser_ui.cjs
 * Set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH when using an existing browser.
 * All HTTP responses below are explicit test fixtures; no live service is used.
 */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

const origin = "https://portal.example.test";
const assets = path.resolve(__dirname, "../assets");
let browser;
before(async () => {
  browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}) });
});
after(async () => { await browser?.close(); });

async function fixture(options = {}) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  await context.addCookies([{ name: "__Host-zecwec_csrf", value: "fixture_csrf", url: origin, secure: true, sameSite: "Strict" }]);
  const page = await context.newPage();
  const state = { signedIn: options.signedIn ?? true, username: "fixture_miner", workers: [], settings: [], requests: [], errors: [], telemetryAvailable: true, balanceFailure: false, holdWorker: null, ...options };
  page.on("pageerror", (error) => state.errors.push(error.message));
  await context.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    assert.equal(url.origin, origin, "UI must use only its own origin");
    const method = request.method();
    const payload = request.postData() ? JSON.parse(request.postData()) : null;
    state.requests.push({ path: url.pathname, method, payload, csrf: request.headers()["x-csrf-token"] });
    const reply = (body, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (url.pathname === "/") return route.fulfill({ contentType: "text/html", body: fs.readFileSync(path.join(assets, "index.html"), "utf8") });
    if (url.pathname.startsWith("/assets/")) {
      const name = url.pathname.slice(8);
      assert.ok(["app.js", "app.css", "forms.css"].includes(name));
      return route.fulfill({ contentType: name.endsWith(".js") ? "text/javascript" : "text/css", body: fs.readFileSync(path.join(assets, name), "utf8") });
    }
    if (url.pathname === "/api/v1/auth/register") return reply({ account: { username: payload.username } }, 201);
    if (url.pathname === "/api/v1/auth/login") { state.signedIn = true; state.username = payload.username; return reply({ csrf_token: "fixture_csrf" }); }
    if (url.pathname === "/api/v1/auth/logout") { state.signedIn = false; return reply({}); }
    if (!state.signedIn) return reply({ message: "Not authenticated." }, 401);
    if (url.pathname === "/api/v1/me") return reply({ id: "fixture-account", username: state.username, totp_enabled: false });
    if (url.pathname === "/readyz") return reply({ status: "ok" });
    if (url.pathname === "/api/v1/overview") return reply({ available: true, updated_at: 1789344000, hashrate_sol_s: null, active_workers: 0, wcash_height: 48, zcash_height: 4343148, wec_fee_bps: 0, zec_fee_bps: 0, wec_maximum_network_fee_zat: 10000, zec_maximum_network_fee_zat: 10000, wec_maximum_network_fee_bps: 100, zec_maximum_network_fee_bps: 100 });
    if (url.pathname === "/api/v1/balances") {
      if (state.balanceFailure) return reply({ message: "Fixture balance unavailable." }, 503);
      return reply({ balances: ["wec", "zec"].map((asset) => ({ asset, total_zat: 0, immature_zat: 0, payable_zat: 0, pending_zat: 0 })) });
    }
    if (url.pathname === "/api/v1/telemetry") return reply({ available: state.telemetryAvailable, updated_at: 1789344000, active_workers: 0, accepted: 0, stale: 0, invalid: 0, duplicate: 0, workers: [] });
    if (url.pathname === "/api/v1/workers") {
      if (method === "POST") {
        if (state.holdWorker) await state.holdWorker;
        const worker = { id: "fixture-worker", label: payload.label, mining_username: `${state.username}.${payload.label}`, revoked_at: null };
        state.workers.push(worker);
        return reply({ worker: { ...worker, token: "zw1.fixture-selector.fixture-only-token" } }, 201);
      }
      return reply({ workers: state.workers });
    }
    if (url.pathname === "/api/v1/settings/payouts") return reply({ settings: state.settings });
    if (url.pathname.startsWith("/api/v1/settings/payouts/")) {
      const asset = url.pathname.split("/").pop();
      const setting = { asset, network: "testnet", active_destination: null, active_receiver: null, threshold_zat: 0, automatic: false, revision: 0, pending_destination: "fixture…masked", pending_threshold_zat: payload.threshold_zat, pending_automatic: payload.automatic, pending_effective_at: 1789516800, pending_revision: 1 };
      state.settings = [...state.settings.filter((item) => item.asset !== asset), setting];
      return reply(setting);
    }
    if (["/api/v1/rewards", "/api/v1/blocks", "/api/v1/payouts"].includes(url.pathname)) return reply({ items: [], next_before: null });
    return reply({ message: "Unimplemented fixture route." }, 404);
  });
  await page.goto(origin);
  if (state.signedIn) await page.locator("#wec-balance").filter({ hasText: "0.00000000 TWC" }).waitFor();
  else await page.locator("#auth-view").waitFor({ state: "visible" });
  return { page, context, state };
}

test("registration keeps the existing account API and does not require an authenticator", async () => {
  const { page, context, state } = await fixture({ signedIn: false });
  try {
    await page.getByRole("button", { name: "Create account", exact: true }).first().click();
    await page.locator("#auth-username").fill("new_miner");
    await page.locator("#auth-password").fill("fixture-password-only");
    assert.equal(await page.locator("#totp-login-field").isVisible(), false);
    await page.locator("#auth-submit").click();
    await page.getByText("Account created. Sign in to continue.").waitFor();
    const registration = state.requests.find((item) => item.path.endsWith("/register"));
    assert.deepEqual(Object.keys(registration.payload).sort(), ["password", "username"]);
    assert.equal(await page.locator("#auth-password").inputValue(), "");
    await page.locator("#auth-password").fill("fixture-password-only");
    await page.locator("#auth-submit").click();
    await page.locator("#app-view").waitFor({ state: "visible" });
    assert.equal(await page.locator("#account-name").textContent(), "new_miner");
    assert.deepEqual(state.errors, []);
  } finally { await context.close(); }
});

test("worker connection uses published TLS/TCP endpoints and clears its one-time token", async () => {
  const { page, context, state } = await fixture();
  try {
    await page.getByRole("button", { name: "Workers", exact: true }).click();
    assert.equal(await page.locator("#stratum-url").inputValue(), "stratum+ssl://testnet-mine.zecwec.com:3443");
    await page.locator("#stratum-transport").selectOption("tcp");
    assert.equal(await page.locator("#stratum-url").inputValue(), "stratum+tcp://testnet-mine.zecwec.com:3333");
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async () => { throw new Error("Fixture clipboard denial"); } } }));
    await page.getByRole("button", { name: "Copy URL", exact: true }).click();
    await page.getByText("Value selected. Press Ctrl+C or ⌘C to copy.").waitFor();
    assert.equal(await page.locator("#stratum-url").evaluate((input) => input.selectionEnd - input.selectionStart), (await page.locator("#stratum-url").inputValue()).length);
    await page.getByRole("button", { name: "Add worker", exact: true }).click();
    await page.locator("#worker-label").fill("rig-01");
    await page.getByRole("button", { name: "Create worker token", exact: true }).click();
    await page.locator("#issued-worker-token").waitFor();
    assert.equal(await page.locator("#issued-worker-username").inputValue(), "fixture_miner.rig-01");
    const issued = state.requests.find((item) => item.path === "/api/v1/workers" && item.method === "POST");
    assert.deepEqual(issued.payload, { label: "rig-01" });
    assert.equal(issued.csrf, "fixture_csrf");
    assert.equal(await page.getByRole("button", { name: "Create worker token", exact: true }).isDisabled(), true);
    await page.getByRole("button", { name: "Overview", exact: true }).click();
    assert.equal(await page.locator("#worker-secret").textContent(), "");
    assert.equal(await page.locator("#issued-worker-token").count(), 0);
    assert.deepEqual(state.errors, []);
  } finally { await context.close(); }
});

test("payouts submit exact coin amounts, preserve the other chain, and display the server hold", async () => {
  const { page, context, state } = await fixture();
  try {
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.locator("#wec-destination").fill("fixture-wcash-draft");
    await page.locator("#wec-threshold").fill("0.20000000");
    await page.locator("#zec-address-type").selectOption("transparent");
    assert.match(await page.locator("#zec-address-help").textContent(), /public on the chain/);
    await page.locator("#zec-destination").fill("fixture-zcash-transparent-destination");
    await page.locator("#zec-threshold").fill("1.23456789");
    await page.locator("#zec-password").fill("fixture-password-only");
    await page.getByRole("button", { name: "Save ZEC destination", exact: true }).click();
    await page.locator('.payout-form[data-asset="zec"] .setting-result').filter({ hasText: "Saved." }).waitFor();
    const saved = state.requests.find((item) => item.path === "/api/v1/settings/payouts/zec" && item.method === "PUT");
    assert.equal(saved.payload.threshold_zat, 123456789);
    assert.equal(saved.csrf, "fixture_csrf");
    assert.deepEqual(Object.keys(saved.payload).sort(), ["automatic", "destination", "password", "threshold_zat"]);
    assert.equal(await page.locator("#wec-destination").inputValue(), "fixture-wcash-draft");
    assert.equal(await page.locator("#wec-threshold").inputValue(), "0.20000000");
    assert.equal(await page.locator("#zec-destination").inputValue(), "");
    assert.equal(await page.locator("#zec-password").inputValue(), "");
    assert.match(await page.locator('[data-setting-summary="zec"]').textContent(), /Safety hold until/);
    assert.match(await page.locator("#zec-payout-status").textContent(), /Payouts on hold until/);
    const exact = await page.evaluate(() => ({ tiny: parseCoinInput("0.00000001"), edge: parseCoinInput("21000000.00000000"), rendered: coinInputValue(123456789) }));
    assert.deepEqual(exact, { tiny: 1, edge: 2100000000000000, rendered: "1.23456789" });
    for (const value of ["0", "-1", "1e3", "0.000000001", "21000000.00000001", "90071992.54740991"]) {
      assert.equal(await page.evaluate((candidate) => { try { parseCoinInput(candidate); return false; } catch { return true; } }, value), true);
    }
    await page.getByText("Supported Zcash addresses", { exact: true }).click();
    assert.equal(await page.getByText("Transparent: Zcash Testnet P2PKH or P2SH. Shielded: an Ironwood-capable Unified Address. Bare Sapling and TEX addresses are not supported.", { exact: true }).isVisible(), true);
    assert.deepEqual(state.errors, []);
  } finally { await context.close(); }
});

test("missing telemetry and failed balances stay unavailable rather than becoming zeros", async () => {
  const { page, context, state } = await fixture({ workers: [{ id: "fixture-worker", label: "rig-01", mining_username: "fixture_miner.rig-01", revoked_at: null }] });
  try {
    state.telemetryAvailable = false;
    state.balanceFailure = true;
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await page.locator("#wec-balance").filter({ hasText: "Unavailable" }).waitFor();
    assert.equal(await page.locator("#wec-payable").textContent(), "—");
    assert.equal(await page.locator("#miner-active-workers").textContent(), "Unavailable");
    await page.getByRole("button", { name: "Workers", exact: true }).click();
    await page.locator("#workers-body").filter({ hasText: "Unknown" }).waitFor();
    const cells = await page.locator("#workers-body tr").first().locator("td").allTextContents();
    assert.deepEqual(cells.slice(3, 7), ["—", "—", "—", "—"]);
    assert.deepEqual(state.errors, []);
  } finally { await context.close(); }
});

test("late worker creation cannot repopulate credentials after sign-out", async () => {
  let release;
  const holdWorker = new Promise((resolve) => { release = resolve; });
  const { page, context, state } = await fixture({ holdWorker });
  try {
    await page.getByRole("button", { name: "Workers", exact: true }).click();
    await page.getByRole("button", { name: "Add worker", exact: true }).click();
    await page.locator("#worker-label").fill("pending-worker");
    await page.getByRole("button", { name: "Create worker token", exact: true }).click();
    await page.waitForFunction(() => document.querySelector("#worker-form").dataset.busy === "true");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    release();
    await page.locator("#auth-view").waitFor({ state: "visible" });
    await page.waitForTimeout(50);
    assert.equal(await page.locator("#worker-secret").textContent(), "");
    assert.equal(await page.locator("#issued-worker-token").count(), 0);
    assert.equal(await page.locator("#account-name").textContent(), "");
    assert.deepEqual(state.errors, []);
  } finally { release(); await context.close(); }
});

test("sign-out clears payout metadata and account history states as well as amounts", async () => {
  const { page, context, state } = await fixture({ settings: [{ asset: "wec", active_destination: "fixture…private", active_receiver: "ironwood", threshold_zat: 12345678, automatic: true, revision: 1, pending_destination: null }] });
  try {
    await page.locator("#wec-payout-status").filter({ hasText: "0.12345678 TWC" }).waitFor();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.locator("#auth-view").waitFor({ state: "visible" });
    assert.equal(await page.locator("#wec-payout-status").textContent(), "Checking payout settings");
    assert.equal(await page.locator("#zec-payout-status").textContent(), "Checking payout settings");
    assert.equal(await page.locator("#payouts-state").textContent(), "Sign in");
    assert.doesNotMatch(await page.locator("#app-view").textContent(), /fixture…private|0\.12345678/);
    assert.deepEqual(state.errors, []);
  } finally { await context.close(); }
});

test("untrusted API strings render as text and the shell fits 320px through desktop", async () => {
  const { page, context, state } = await fixture({ workers: [{ id: "fixture-worker", label: '<img src=x onerror="window.bad=true">', mining_username: "fixture.text-only", revoked_at: null }] });
  try {
    await page.getByRole("button", { name: "Workers", exact: true }).click();
    assert.equal(await page.locator("#workers-body img").count(), 0);
    assert.match(await page.locator("#workers-body").textContent(), /<img src=x/);
    for (const width of [320, 360, 736, 1024, 1280]) {
      await page.setViewportSize({ width, height: 1100 });
      for (const name of ["Overview", "Workers", "Settings"]) {
        await page.getByRole("button", { name, exact: true }).click();
        assert.equal(await page.locator(".network").isVisible(), true);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${name} overflows at ${width}px`);
      }
    }
    if (process.env.PORTAL_UI_SCREENSHOT_DIR) {
      fs.mkdirSync(process.env.PORTAL_UI_SCREENSHOT_DIR, { recursive: true });
      await page.setViewportSize({ width: 1280, height: 1100 });
      await page.getByRole("button", { name: "Overview", exact: true }).click();
      await page.screenshot({ path: path.join(process.env.PORTAL_UI_SCREENSHOT_DIR, "overview.png"), fullPage: true });
      await page.setViewportSize({ width: 320, height: 1100 });
      await page.getByRole("button", { name: "Settings", exact: true }).click();
      await page.screenshot({ path: path.join(process.env.PORTAL_UI_SCREENSHOT_DIR, "settings-mobile.png"), fullPage: true });
      await page.emulateMedia({ colorScheme: "dark" });
      await page.setViewportSize({ width: 1024, height: 1100 });
      await page.getByRole("button", { name: "Overview", exact: true }).click();
      await page.screenshot({ path: path.join(process.env.PORTAL_UI_SCREENSHOT_DIR, "overview-dark.png"), fullPage: true });
    }
    assert.deepEqual(state.errors, []);
  } finally { await context.close(); }
});
