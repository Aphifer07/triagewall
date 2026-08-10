const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const {
  startIndependentPolling,
} = require("../triagewall/dashboard/static/polling.js");

const STATIC_DIR = path.join(
  __dirname,
  "..",
  "triagewall",
  "dashboard",
  "static",
);

// A DOM stub small enough to read, but real enough to run dashboard.js end to
// end. It exists so the draft-preservation and focus-tracking guarantees are
// proven by executing the shipped script rather than by matching its text.
function createElement(id) {
  const listeners = new Map();
  let innerHTML = "";
  const element = {
    id,
    value: "",
    textContent: "",
    disabled: false,
    hidden: false,
    title: "",
    focused: false,
    innerHTMLWrites: 0,
    dataset: {},
    style: {},
    classList: {
      add() {},
      remove() {},
      toggle() {},
      contains: () => false,
    },
    setAttribute() {},
    removeAttribute() {},
    getAttribute: () => null,
    scrollIntoView() {},
    querySelectorAll: () => [],
    closest: () => null,
    focus() {
      this.focused = true;
    },
    addEventListener(type, handler) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(handler);
    },
    dispatch(type, event) {
      (listeners.get(type) ?? []).forEach((handler) => handler(event));
    },
  };
  Object.defineProperty(element, "innerHTML", {
    get: () => innerHTML,
    set(value) {
      innerHTML = value;
      element.innerHTMLWrites += 1;
    },
  });
  return element;
}

function runDashboard({ pathname, verdicts = [] }) {
  const elements = new Map();
  const documentListeners = new Map();
  const intervals = [];
  const pushedUrls = [];

  const document = {
    title: "",
    body: { classList: { add() {}, remove() {}, toggle() {} } },
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, createElement(id));
      return elements.get(id);
    },
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener(type, handler) {
      if (!documentListeners.has(type)) documentListeners.set(type, []);
      documentListeners.get(type).push(handler);
    },
  };

  const json = (body) =>
    Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

  const fetchCalls = [];
  const fetchStub = (url, options) => {
    const target = String(url);
    fetchCalls.push({ url: target, options });
    if (target.includes("/api/health")) {
      return json({ status: "ok", last_alert_age_seconds: 1, storage: {} });
    }
    if (target.includes("/api/v1/stats")) return json({ mode: "local", stats: {} });
    if (target.includes("/api/v1/spc-anomalies")) {
      return json({ available: false, anomalies: [] });
    }
    if (target.includes("/investigation")) {
      return json({
        window_hours: 24,
        recurrence: {
          available: true,
          signature_id: 1,
          source_type: "suricata",
          occurrences: 1,
          first_seen: null,
          last_seen: null,
          real_count: 1,
          false_positive_count: 0,
          uncertain_count: 0,
          unclassified_count: 0,
        },
        related: [],
        neighbors: { previous: null, next: null },
      });
    }
    if (/\/api\/v1\/verdicts\/\d+$/.test(target)) {
      return json({
        mode: "local",
        verdict: {
          id: 7,
          verdict: "real",
          signature: "sig",
          confidence: 0.9,
          sensor_context: { source: "suricata" },
        },
      });
    }
    return json({ mode: "local", verdicts, next_cursor: null });
  };

  const sandbox = {
    document,
    window: {
      location: {
        pathname,
        search: "",
        href: `http://localhost${pathname}`,
      },
      history: {
        pushState(_state, _title, url) {
          pushedUrls.push(url);
        },
        replaceState() {},
      },
      addEventListener() {},
      scrollTo() {},
    },
    fetch: fetchStub,
    // The real polling module, with its scheduler captured so ticks are fired
    // by the test rather than by a live 30s timer.
    startIndependentPolling: (options) =>
      startIndependentPolling({
        ...options,
        setTimer: (handler) => intervals.push(handler),
      }),
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    console,
    navigator: {},
  };
  sandbox.globalThis = sandbox;

  vm.runInNewContext(
    fs.readFileSync(path.join(STATIC_DIR, "dashboard.js"), "utf8"),
    sandbox,
    { filename: "dashboard.js" },
  );

  return {
    document,
    fetchCalls,
    pushedUrls,
    tick: () => intervals.forEach((handler) => handler()),
    dispatchKey: (key, target = { tagName: "DIV" }) =>
      (documentListeners.get("keydown") ?? []).forEach((handler) =>
        handler({ key, target, preventDefault() {} }),
      ),
    async settle() {
      for (let index = 0; index < 40; index += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
    },
  };
}

test("starts SPC without waiting for the main dashboard request", () => {
  const calls = [];
  const timers = [];

  startIndependentPolling({
    loadMain: () => {
      calls.push("main");
      return new Promise(() => {});
    },
    loadSpc: () => calls.push("spc"),
    setTimer: (callback, delay) => timers.push({ callback, delay }),
  });

  assert.deepEqual(calls, ["spc", "main"]);
  assert.equal(timers.length, 2);
  assert.deepEqual(timers.map(({ delay }) => delay), [30_000, 30_000]);
});

test("keeps SPC polling when the main dashboard request fails", async () => {
  let mainCalls = 0;
  let spcCalls = 0;
  const errors = [];
  const timers = [];

  startIndependentPolling({
    loadMain: () => {
      mainCalls += 1;
      return Promise.reject(new Error("verdicts unavailable"));
    },
    loadSpc: () => {
      spcCalls += 1;
    },
    setTimer: (callback) => timers.push(callback),
    onError: (error) => errors.push(error.message),
  });

  await Promise.resolve();
  assert.equal(mainCalls, 1);
  assert.equal(spcCalls, 1);
  assert.deepEqual(errors, ["verdicts unavailable"]);

  timers.forEach((callback) => callback());
  await Promise.resolve();
  assert.equal(mainCalls, 2);
  assert.equal(spcCalls, 2);
  assert.deepEqual(errors, ["verdicts unavailable", "verdicts unavailable"]);
});

test("dashboard wires SPC outside the verdict-loading function", () => {
  const scriptPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "dashboard.js",
  );
  const script = fs.readFileSync(scriptPath, "utf8");
  const loadStart = script.indexOf("async function load({");
  const loadEnd = script.indexOf("function renderHealth", loadStart);

  assert.notEqual(loadStart, -1);
  assert.notEqual(loadEnd, -1);
  assert.doesNotMatch(script.slice(loadStart, loadEnd), /loadSpc\s*\(/);
  assert.match(script, /startIndependentPolling\(\{\s*\n\s*loadMain: \(\) => \{/);
  assert.match(script, /\n\s*loadSpc,\n\}\);/);

  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");
  assert.match(html, /<script src="\/static\/polling\.js"><\/script>/);
  assert.match(html, /<script src="\/static\/dashboard\.js"><\/script>/);
});

test("dashboard renders source-aware labels and escapes dynamic identifiers", () => {
  const scriptPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "dashboard.js",
  );
  const script = fs.readFileSync(scriptPath, "utf8");

  assert.match(script, /sensor === "wazuh" \? "Rule" : "SID"/);
  assert.match(script, /Agent \$\{agent\.name\}/);
  assert.match(script, /<span class="queue-endpoint queue-source">\$\{escapeHtml\(source\)\}<\/span>/);
  assert.match(script, /SID \$\{escapeHtml\(anomaly\.signature_id\)\}/);
  assert.match(
    script,
    /\$\{ruleLabel\} \$\{escapeHtml\(verdict\.signature_id \?\? "\?"\)\}/,
  );
  assert.match(script, /badge badge-sensor/);
});

test("dashboard renders storage allocation from the health endpoint", () => {
  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");
  const script = fs.readFileSync(
    path.join(path.dirname(indexPath), "dashboard.js"),
    "utf8",
  );

  assert.match(html, /id="storageMeta"/);
  assert.match(script, /storage\.total_on_disk_bytes/);
  assert.match(script, /function formatBytes\(value\)/);
});

test("dashboard has no runtime dependency on third-party CDNs", () => {
  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");

  assert.doesNotMatch(html, /cdn\.|fonts\.googleapis|fonts\.gstatic/i);
  assert.match(html, /href="\/static\/dashboard\.css"/);
});

test("dashboard uses separate queue, overview, behavioral, and integrity views", () => {
  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");

  assert.ok(html.indexOf('data-view="triage"') < html.indexOf('data-view="overview"'));
  assert.match(html, /class="decision-columns"/);
  assert.match(html, /href="\/triage" data-view-link="triage"/);
  assert.match(html, /href="\/overview" data-view-link="overview"/);
  assert.match(html, /href="\/behavioral" data-view-link="behavioral"/);
  assert.match(html, /href="\/integrity" data-view-link="integrity"/);
  assert.match(html, /data-view="integrity"/);
  assert.match(html, /Implemented controls — not inferred incident counters/);
  assert.doesNotMatch(html, />Cases<\/a>|>Reports<\/a>|>Hunt<\/a>/);
});

test("dashboard uses cursor pagination and URL-backed queue filters", () => {
  const script = fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "triagewall",
      "dashboard",
      "static",
      "dashboard.js",
    ),
    "utf8",
  );

  assert.match(script, /const PAGE_SIZE = 50;/);
  assert.match(script, /params\.set\("limit", String\(PAGE_SIZE\)\)/);
  assert.match(script, /params\.set\("cursor", cursor\)/);
  assert.match(script, /window\.history\.replaceState/);
  assert.match(script, /currentFilter\.source/);
  assert.match(script, /currentFilter\.review/);
  assert.match(script, /decisions loaded/);
});

test("dashboard detail route escapes raw events and supports review notes", () => {
  const staticDir = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
  );
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const script = fs.readFileSync(path.join(staticDir, "dashboard.js"), "utf8");

  assert.match(html, /data-view="detail"/);
  assert.match(html, /id="detailPageContent"/);
  assert.doesNotMatch(html, /<dialog id="detailDrawer"/);
  assert.match(script, /\/api\/v1\/verdicts\/\$\{eventId\}/);
  assert.match(script, /<pre class="raw-event">\$\{escapeHtml\(rawAlert\)\}<\/pre>/);
  assert.match(script, /id="detailNotes" maxlength="2000"/);
  assert.match(script, /notes \}\),/);
});

function readDashboardScript() {
  return fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "triagewall",
      "dashboard",
      "static",
      "dashboard.js",
    ),
    "utf8",
  );
}

test("detail navigation preserves the queue query string", () => {
  const script = readDashboardScript();

  assert.match(script, /function queueQueryString\(\)/);
  // Opening an alert, leaving it, and the back link all carry the filters.
  assert.match(script, /`\/triage\/\$\{eventId\}\$\{queueQueryString\(\)\}`/);
  assert.match(script, /`\/triage\$\{queueQueryString\(\)\}`/);
  assert.match(script, /function syncQueueLinks\(\)/);
  // The old behaviour pushed a bare path and dropped the analyst's view.
  assert.doesNotMatch(script, /pushState\(\{\}, "", "\/triage"\)/);
  assert.doesNotMatch(
    script,
    /pushState\(\{\}, "", `\/triage\/\$\{Number\(verdict\.id\)\}`\)/,
  );
});

test("previous and next come from the server, not the loaded page", () => {
  const script = readDashboardScript();

  assert.match(
    script,
    /\/api\/v1\/verdicts\/\$\{eventId\}\/investigation\?\$\{params\}/,
  );
  assert.match(script, /function renderDetailNavigation\(neighbors\)/);
  assert.match(script, /neighbors\?\.previous \?\? null/);
  assert.match(script, /neighbors\?\.next \?\? null/);
  // Deep links and refreshes have no loaded queue page to index into.
  assert.doesNotMatch(script, /currentVerdicts\.findIndex/);
});

test("investigation panels escape sensor text and state their scope", () => {
  const script = readDashboardScript();

  assert.match(script, /function renderRecurrence\(data\)/);
  assert.match(script, /function renderRelated\(data\)/);
  assert.match(script, /id="relatedPanel"/);
  assert.match(script, /id="recurrencePanel"/);
  // Sensor-controlled strings are escaped everywhere they are rendered.
  assert.match(
    script,
    /<span class="related-signature">\$\{escapeHtml\(alert\.signature \?\? "Unnamed alert"\)\}<\/span>/,
  );
  assert.match(script, /\$\{escapeHtml\(group\.reason\)\}/);
  assert.match(
    script,
    /\$\{escapeHtml\(relatedScopeNote\(group, data\.window_hours\)\)\}/,
  );
  // Every group says why it is related, and a bounded scan admits it is partial.
  assert.match(script, /function relatedScopeNote\(group, windowHours\)/);
  assert.match(script, /related-scope-partial/);
  assert.match(script, /so older matches in this window are not shown/);
  // Recurrence is namespaced by source type, not by signature id alone.
  assert.match(script, /Suricata and Wazuh identifiers are counted separately/);
});

test("source-specific context is derived only from the retained record", () => {
  const script = readDashboardScript();

  assert.match(script, /function renderSourceContext\(verdict, sensor\)/);
  assert.match(
    script,
    /sensor === "wazuh" \? "Wazuh rule context" : "Suricata flow context"/,
  );
  // Wazuh-only fields never appear under Suricata labels and vice versa.
  assert.match(script, /readRawScalar\(raw, \["manager", "name"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["location"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["decoder", "name"\]\)/);
  assert.match(script, /readRawList\(raw, \["rule", "groups"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["in_iface"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["pkt_src"\]\)/);
  // Absent values are stated, not blanked, and nested objects are rejected.
  assert.match(script, /function derivedField\(label, value\)/);
  assert.match(script, /"Not recorded"/);
  assert.match(script, /typeof value === "object"\) return null;/);
});

test("a deep link still loads the detail view on the initial load", async () => {
  const harness = runDashboard({ pathname: "/triage/7" });
  await harness.settle();

  const urls = harness.fetchCalls.map(({ url }) => url);
  assert.ok(urls.some((url) => url.endsWith("/api/v1/verdicts/7")));
  assert.ok(urls.some((url) => url.includes("/api/v1/verdicts/7/investigation")));
  assert.ok(harness.document.getElementById("detailPageContent").innerHTMLWrites > 0);
});

test("detail and investigation are fetched with no-store", async () => {
  const harness = runDashboard({ pathname: "/triage/7" });
  await harness.settle();

  const perEvent = harness.fetchCalls.filter(({ url }) =>
    /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  );
  assert.equal(perEvent.length, 2);
  for (const call of perEvent) {
    assert.equal(call.options?.cache, "no-store", `missing no-store for ${call.url}`);
  }
});

test("a scheduled polling tick preserves an unsaved review note", async () => {
  const harness = runDashboard({ pathname: "/triage/7" });
  await harness.settle();

  const notes = harness.document.getElementById("detailNotes");
  notes.value = "half-written justification";
  const detail = harness.document.getElementById("detailPageContent");
  const writesBeforeTick = detail.innerHTMLWrites;
  const fetchesBeforeTick = harness.fetchCalls.length;

  harness.tick();
  await harness.settle();

  assert.equal(notes.value, "half-written justification");
  assert.equal(
    detail.innerHTMLWrites,
    writesBeforeTick,
    "polling replaced the detail DOM and destroyed the draft",
  );
  // Health and stats must keep refreshing while the detail body is left alone.
  const polled = harness.fetchCalls.slice(fetchesBeforeTick).map(({ url }) => url);
  assert.ok(polled.some((url) => url.includes("/api/health")));
  assert.ok(polled.some((url) => url.includes("/api/v1/stats")));
  assert.ok(!polled.some((url) => /\/api\/v1\/verdicts\/7/.test(url)));
});

test("focusing a queue card syncs the index so Enter opens that card", async () => {
  const verdicts = [
    { id: 11, verdict: "real", signature: "one", confidence: 0.5 },
    { id: 22, verdict: "real", signature: "two", confidence: 0.5 },
    { id: 33, verdict: "real", signature: "three", confidence: 0.5 },
  ];
  const harness = runDashboard({ pathname: "/triage", verdicts });
  await harness.settle();

  // Tab moves DOM focus to the third card without touching the arrow keys.
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "2" } }) },
  });
  harness.dispatchKey("Enter");
  await harness.settle();

  assert.ok(
    harness.pushedUrls.some((url) => String(url).startsWith("/triage/33")),
    `expected the focused card to open, got ${JSON.stringify(harness.pushedUrls)}`,
  );
});

test("D opens the focused alert with the review note focused", async () => {
  const verdicts = [
    { id: 11, verdict: "real", signature: "one", confidence: 0.5, human_verdict: null },
  ];
  const harness = runDashboard({ pathname: "/triage", verdicts });
  await harness.settle();

  harness.dispatchKey("d");
  await harness.settle();

  assert.ok(harness.pushedUrls.some((url) => String(url).startsWith("/triage/11")));
  assert.equal(harness.document.getElementById("detailNotes").focused, true);
});

test("the queue search advertises only what it actually searches", () => {
  const html = fs.readFileSync(path.join(STATIC_DIR, "index.html"), "utf8");

  // The filter is a signature LIKE; it does not search IPs or rule ids.
  assert.match(html, /id="sigFilter"[^>]*placeholder="signature text…"/);
  assert.doesNotMatch(html, /placeholder="[^"]*\bIP\b/);
  assert.doesNotMatch(html, /placeholder="[^"]*rule id/);
  // The shortcut legend must describe what D now does.
  assert.match(html, /<kbd>D<\/kbd> Review/);
  assert.doesNotMatch(html, /<kbd>D<\/kbd> Correct/);
});

test("overview uses a truthful policy-to-model decision band", () => {
  const staticDir = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
  );
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const script = fs.readFileSync(path.join(staticDir, "dashboard.js"), "utf8");

  assert.match(html, /id="prefilterRate"/);
  assert.match(html, /id="policyBand"/);
  assert.match(html, /Includes deterministic policy/);
  assert.match(script, /stats\.today_prefilter/);
  assert.match(script, /stats\.today_llm/);
  assert.match(script, /stats\.model_real_count/);
  assert.match(script, /stats\.unreviewed_model_count/);
});
