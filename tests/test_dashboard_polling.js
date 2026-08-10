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

function runDashboard({ pathname, search = "", verdicts = [], defer = () => false }) {
  const elements = new Map();
  const documentListeners = new Map();
  const intervals = [];
  const pushedUrls = [];
  const deferred = [];
  const windowListeners = new Map();
  const saved = new Map();

  const document = {
    title: "",
    body: { classList: { add() {}, remove() {}, toggle() {} } },
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, createElement(id));
      return elements.get(id);
    },
    // Only id selectors resolve. That is enough for the listeners the script
    // attaches by id, and anything else yields an empty list rather than a
    // fake element that would make a test pass for the wrong reason.
    querySelectorAll(selector) {
      const parts = String(selector).split(",").map((part) => part.trim());
      if (!parts.every((part) => /^#[\w-]+$/.test(part))) return [];
      return parts.map((part) => this.getElementById(part.slice(1)));
    },
    querySelector: () => null,
    addEventListener(type, handler) {
      if (!documentListeners.has(type)) documentListeners.set(type, []);
      documentListeners.get(type).push(handler);
    },
  };

  const response = (body) => ({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  });

  // Bodies are derived from the requested id so a response can be traced back
  // to the navigation that asked for it.
  function bodyFor(target) {
    if (target.includes("/api/health")) {
      return { status: "ok", last_alert_age_seconds: 1, storage: {} };
    }
    if (target.includes("/api/v1/stats")) return { mode: "local", stats: {} };
    if (target.includes("/api/v1/spc-anomalies")) {
      return { available: false, anomalies: [] };
    }
    const feedback = target.match(/\/api\/v1\/feedback\/(\d+)$/);
    if (feedback) return { ok: true, agreed: true };
    const investigation = target.match(/\/api\/v1\/verdicts\/(\d+)\/investigation/);
    if (investigation) {
      const id = Number(investigation[1]);
      return {
        window_hours: 24,
        recurrence: {
          available: true,
          signature_id: id,
          source_type: "suricata",
          occurrences: 1,
          first_seen: null,
          last_seen: null,
          real_count: 1,
          false_positive_count: 0,
          uncertain_count: 0,
          unclassified_count: 0,
        },
        related: [
          {
            relationship: "same_rule",
            label: "Same rule",
            reason: "same rule",
            exact: true,
            truncated: false,
            candidate_limit: null,
            candidates_examined: null,
            alerts: [
              {
                id: id * 10,
                timestamp: null,
                processed_at: null,
                signature_id: id,
                signature: `related-of-${id}`,
                verdict: "real",
                confidence: 0.5,
                src_ip: null,
                dest_ip: null,
                source_type: "suricata",
                relationship: "same_rule",
              },
            ],
          },
        ],
        neighbors: {
          previous: { id: 1000 + id, signature: `previous-of-${id}` },
          next: { id: 2000 + id, signature: `next-of-${id}` },
        },
      };
    }
    const detail = target.match(/\/api\/v1\/verdicts\/(\d+)$/);
    if (detail) {
      const id = Number(detail[1]);
      return {
        mode: "local",
        verdict: {
          id,
          verdict: "real",
          signature: `signature-${id}`,
          confidence: 0.9,
          sensor_context: { source: "suricata" },
        },
      };
    }
    const list = target.match(/\/api\/v1\/verdicts\?(.*)$/);
    if (list) {
      const params = new URLSearchParams(list[1]);
      const tag = params.get("model") || "any";
      const cursor = params.get("cursor");
      // Rows are tagged with the filter that asked for them, so a response can
      // be traced back to the request that produced it.
      const rows = verdicts.length
        ? verdicts
        : [
            {
              id: cursor ? 900 : 100,
              verdict: "real",
              signature: `row-${tag}${cursor ? "-older" : ""}`,
              confidence: 0.5,
              human_verdict: null,
            },
          ];
      // The server is the source of truth for review state: once feedback has
      // been saved, every later read reflects it. That is what no-store buys.
      return {
        mode: "local",
        verdicts: rows.map((row) =>
          saved.has(row.id) ? { ...row, ...saved.get(row.id) } : row,
        ),
        next_cursor: cursor ? null : `cursor-${tag}`,
      };
    }
    return { mode: "local", verdicts, next_cursor: null };
  }

  const fetchCalls = [];
  const fetchStub = (url, options) => {
    const target = String(url);
    fetchCalls.push({ url: target, options });
    const posted = target.match(/\/api\/v1\/feedback\/(\d+)$/);
    if (posted && options?.method === "POST") {
      const payload = JSON.parse(options.body);
      saved.set(Number(posted[1]), {
        human_verdict: payload.human_verdict,
        human_notes: payload.notes,
        agreed: 1,
      });
    }
    const body = bodyFor(target);
    if (defer(target)) {
      return new Promise((resolve) => {
        deferred.push({ url: target, release: () => resolve(response(body)) });
      });
    }
    return Promise.resolve(response(body));
  };

  // A real location object: pushState moves it, so the script's own
  // "am I still on this alert?" checks are exercised rather than stubbed out.
  const location = { pathname, search, href: `http://localhost${pathname}${search}` };
  const navigate = (url) => {
    const [nextPath, query = ""] = String(url).split("?");
    location.pathname = nextPath;
    location.search = query ? `?${query}` : "";
    location.href = `http://localhost${url}`;
  };

  const sandbox = {
    document,
    AbortController,
    window: {
      location,
      history: {
        pushState(_state, _title, url) {
          pushedUrls.push(url);
          navigate(url);
        },
        replaceState(_state, _title, url) {
          if (url) navigate(url);
        },
      },
      addEventListener(type, handler) {
        if (!windowListeners.has(type)) windowListeners.set(type, []);
        windowListeners.get(type).push(handler);
      },
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

  // Appended in the same lexical scope so the probe can read the script's
  // top-level `let` bindings, which vm does not expose on the sandbox object.
  const probe = `
;globalThis.__probe = {
  open: (id, options) => openDetailById(id, options),
  setFilter: (key, value) => { currentFilter[key] = value; },
  applyFilters: () => applyFilters(),
  loadOlder: () => loadOlder(),
  state: () => ({
    currentView,
    activeDetail,
    activeInvestigation,
    currentFilter: { ...currentFilter },
    currentVerdicts: currentVerdicts.map((row) => ({ ...row })),
    nextCursor,
  }),
};`;

  vm.runInNewContext(
    fs.readFileSync(path.join(STATIC_DIR, "dashboard.js"), "utf8") + probe,
    sandbox,
    { filename: "dashboard.js" },
  );

  return {
    document,
    fetchCalls,
    pushedUrls,
    location,
    api: sandbox.__probe,
    deferred,
    releaseDeferred: () => {
      const queued = deferred.splice(0, deferred.length);
      queued.forEach(({ release }) => release());
    },
    tick: () => intervals.forEach((handler) => handler()),
    // Simulates the browser restoring a history entry: move the URL, then
    // deliver popstate, exactly as a back/forward press would.
    goBackTo(url) {
      navigate(url);
      (windowListeners.get("popstate") ?? []).forEach((handler) => handler({}));
    },
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

test("a superseded detail navigation cannot overwrite the current alert", async () => {
  // Alert 7's detail and investigation responses are held open; alert 8's
  // resolve immediately.
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [{ id: 7, verdict: "real", signature: "seven", confidence: 0.5 }],
    defer: (url) => /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  });
  await harness.settle();

  harness.api.open(7);
  await harness.settle();
  assert.ok(harness.deferred.length > 0, "alert 7 should still be in flight");

  harness.api.open(8);
  await harness.settle();

  // Alert 7 answers only now, after the operator has moved to alert 8.
  harness.releaseDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(harness.location.pathname, "/triage/8");
  assert.equal(state.currentView, "detail");
  assert.equal(state.activeDetail.id, 8);
  assert.equal(state.activeInvestigation.recurrence.signature_id, 8);

  const detail = harness.document.getElementById("detailPageContent").innerHTML;
  assert.match(detail, /signature-8/);
  assert.doesNotMatch(detail, /signature-7/);

  const related = harness.document.getElementById("relatedPanel").innerHTML;
  assert.match(related, /related-of-8/);
  assert.doesNotMatch(related, /related-of-7/);
  assert.doesNotMatch(related, /temporarily unavailable/);

  const recurrence = harness.document.getElementById("recurrencePanel").innerHTML;
  assert.doesNotMatch(recurrence, /temporarily unavailable/);

  assert.equal(
    harness.document.getElementById("previousAlertButton").dataset.eventId,
    1008,
  );
  assert.equal(
    harness.document.getElementById("nextAlertButton").dataset.eventId,
    2008,
  );

  // Feedback raised from the detail page must target the alert on screen.
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: "real" } }
          : null,
    },
  });
  await harness.settle();
  const posted = harness.fetchCalls.filter(({ url }) => url.includes("/api/v1/feedback/"));
  assert.equal(posted.length, 1);
  assert.match(posted[0].url, /\/api\/v1\/feedback\/8$/);
});

test("leaving the detail view retires an in-flight request", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  });
  await harness.settle();

  harness.api.open(7);
  await harness.settle();

  harness.dispatchKey("Escape");
  await harness.settle();
  const writesAfterClose =
    harness.document.getElementById("detailPageContent").innerHTMLWrites;

  harness.releaseDeferred();
  await harness.settle();

  assert.equal(harness.location.pathname, "/triage");
  assert.equal(harness.api.state().activeDetail, null);
  assert.equal(
    harness.document.getElementById("detailPageContent").innerHTMLWrites,
    writesAfterClose,
    "a retired request rendered into the detail view after navigating away",
  );
});

test("the queue list is fetched with no-store", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  const listCalls = harness.fetchCalls.filter(({ url }) =>
    /\/api\/v1\/verdicts\?/.test(url),
  );
  assert.ok(listCalls.length > 0);
  for (const call of listCalls) {
    assert.equal(call.options?.cache, "no-store", `missing no-store for ${call.url}`);
  }
});

test("a saved review is visible on return to the queue and blocks a second write", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 11, verdict: "real", signature: "one", confidence: 0.5, human_verdict: null },
    ],
  });
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].human_verdict, null);

  harness.api.open(11);
  await harness.settle();
  harness.document.getElementById("detailNotes").value = "owner confirmed the host";
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: "real" } }
          : null,
    },
  });
  await harness.settle();

  const firstPost = harness.fetchCalls.filter(({ url }) =>
    url.includes("/api/v1/feedback/"),
  );
  assert.equal(firstPost.length, 1);
  assert.equal(JSON.parse(firstPost[0].options.body).notes, "owner confirmed the host");

  // Back to the queue: the refetched row must carry the saved review.
  harness.dispatchKey("Escape");
  await harness.settle();
  const row = harness.api.state().currentVerdicts[0];
  assert.equal(row.human_verdict, "real");
  assert.equal(row.human_notes, "owner confirmed the host");

  // The one-key agree action is guarded on human_verdict, so a stale row would
  // let it fire again and overwrite the saved note with an empty one.
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "0" } }) },
  });
  harness.dispatchKey("a");
  await harness.settle();

  const allPosts = harness.fetchCalls.filter(({ url }) =>
    url.includes("/api/v1/feedback/"),
  );
  assert.equal(allPosts.length, 1, "a second feedback POST was submitted");
});

test("an old filter's response cannot replace the newer filter's rows", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => /\/api\/v1\/verdicts\?.*model=llm/.test(url),
  });
  await harness.settle();
  assert.ok(harness.deferred.length > 0, "the llm query should still be in flight");

  harness.api.setFilter("model", "prefilter");
  harness.api.applyFilters();
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].signature, "row-prefilter");

  // The superseded llm query answers only now.
  harness.releaseDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.currentFilter.model, "prefilter");
  assert.equal(state.currentVerdicts.length, 1);
  assert.equal(state.currentVerdicts[0].signature, "row-prefilter");
  assert.match(harness.document.getElementById("verdicts").innerHTML, /row-prefilter/);
  assert.doesNotMatch(harness.document.getElementById("verdicts").innerHTML, /row-llm/);
  // Retirement is silent: it is not a failure the operator needs to see.
  assert.equal(harness.document.getElementById("toast").textContent, "");
  assert.doesNotMatch(
    harness.document.getElementById("freshness").textContent,
    /unavailable/,
  );
});

test("a filter change invalidates an in-flight Load Older page", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => url.includes("cursor="),
  });
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].signature, "row-llm");
  assert.equal(harness.api.state().nextCursor, "cursor-llm");

  harness.api.loadOlder();
  await harness.settle();
  assert.ok(harness.deferred.length > 0, "the older page should still be in flight");

  harness.api.setFilter("model", "prefilter");
  harness.api.applyFilters();
  await harness.settle();

  // The old-filter page answers after the filters changed.
  harness.releaseDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.currentVerdicts.length, 1, "old-filter rows were appended");
  assert.equal(state.currentVerdicts[0].signature, "row-prefilter");
  assert.doesNotMatch(
    harness.document.getElementById("verdicts").innerHTML,
    /row-llm-older/,
  );
  assert.equal(harness.document.getElementById("toast").textContent, "");
});

test("history restores each entry's own filters", async () => {
  const harness = runDashboard({ pathname: "/triage", search: "?model=llm" });
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.model, "llm");

  // Back to an entry recorded with the policy path selected.
  harness.goBackTo("/triage?model=prefilter");
  await harness.settle();
  let state = harness.api.state();
  assert.equal(state.currentFilter.model, "prefilter");
  assert.equal(state.currentVerdicts[0].signature, "row-prefilter");
  assert.match(harness.fetchCalls.at(-1).url, /model=prefilter/);

  // Forward again to the model entry.
  harness.goBackTo("/triage?model=llm");
  await harness.settle();
  state = harness.api.state();
  assert.equal(state.currentFilter.model, "llm");
  assert.equal(state.currentVerdicts[0].signature, "row-llm");
});

test("history restore clears filters the restored entry does not carry", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&verdict=real&source=wazuh&review=unreviewed&signature=scan",
  });
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.verdict, "real");
  assert.equal(harness.api.state().currentFilter.signature, "scan");

  harness.goBackTo("/triage");
  await harness.settle();

  const state = harness.api.state();
  // Re-spread into this realm: the sandbox object has a different prototype.
  assert.deepEqual({ ...state.currentFilter }, {
    verdict: "",
    signature: "",
    model: "",
    source: "",
    review: "",
  });
  // The visible controls follow the restored state, not the newer memory.
  assert.equal(harness.document.getElementById("sigFilter").value, "");
  assert.equal(harness.document.getElementById("sourceFilter").value, "");
  assert.equal(harness.document.getElementById("reviewFilter").value, "");
  const requested = harness.fetchCalls.at(-1).url;
  assert.doesNotMatch(requested, /verdict=|source=|review=|signature=|model=/);
});

test("a restored detail entry investigates with that entry's filters", async () => {
  const harness = runDashboard({ pathname: "/triage", search: "?model=llm" });
  await harness.settle();

  harness.goBackTo("/triage/5?model=prefilter&review=unreviewed");
  await harness.settle();

  assert.equal(harness.api.state().currentFilter.model, "prefilter");
  assert.equal(harness.api.state().activeDetail.id, 5);
  const investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/5/investigation"))
    .at(-1);
  assert.match(investigation, /model=prefilter/);
  assert.match(investigation, /review=unreviewed/);

  // Previous/next inherit the restored filters too.
  harness.document.getElementById("nextAlertButton").dispatch("click", {});
  await harness.settle();
  assert.match(String(harness.pushedUrls.at(-1)), /^\/triage\/2005\?/);
  assert.match(String(harness.pushedUrls.at(-1)), /model=prefilter/);
});

test("queue badge counts declare their global 24h scope", () => {
  const html = fs.readFileSync(path.join(STATIC_DIR, "index.html"), "utf8");
  const script = readDashboardScript();

  // The badges come from /api/v1/stats, which is a global 24h rollup, so the
  // page must not let them read as counts of the filtered or paged rows.
  assert.match(html, /aria-describedby="queueScopeNote"/);
  assert.match(html, /id="queueScopeNote"/);
  const note = html.match(
    /id="queueScopeNote"[^>]*>([\s\S]*?)<\/p>/,
  )?.[1];
  assert.ok(note, "queue scope note is missing");
  assert.match(note, /global totals/i);
  assert.match(note, /last 24 hours/i);
  // Must stay true when a Policy, source, or review filter is selected.
  assert.match(note, /Policy, source, and review filters/i);
  assert.match(note, /never change them/i);

  // The sidebar badge carries the same scope for assistive technology.
  assert.match(
    html,
    /id="sidebarQueueCount"[^>]*title="Unreviewed model decisions in the last 24 hours, across all filters"/,
  );
  assert.match(html, /<span class="sr-only">unreviewed model decisions in the last 24 hours, across all filters<\/span>/);

  // The queue meta line separates the page count from the global count.
  assert.match(script, /decisions loaded on this page/);
  assert.match(script, /unreviewed in the last 24h, all filters/);
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
