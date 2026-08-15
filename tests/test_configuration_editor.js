const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const SCRIPT = path.join(
  __dirname,
  "..",
  "triagewall",
  "dashboard",
  "static",
  "configuration.js",
);

function createElement(id) {
  const listeners = new Map();
  const classes = new Set();
  return {
    id,
    value: "",
    textContent: "",
    innerHTML: "",
    checked: false,
    disabled: false,
    title: "",
    dataset: {},
    className: "",
    classList: {
      add: (...names) => names.forEach((name) => classes.add(name)),
      remove: (...names) => names.forEach((name) => classes.delete(name)),
      toggle(name, force) {
        const enabled = force === undefined ? !classes.has(name) : Boolean(force);
        if (enabled) classes.add(name);
        else classes.delete(name);
        return enabled;
      },
      contains: (name) => classes.has(name),
    },
    addEventListener(type, handler) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(handler);
    },
    async dispatch(type, event = {}) {
      const payload = {
        preventDefault() {},
        target: this,
        ...event,
      };
      await Promise.all((listeners.get(type) ?? []).map((handler) => handler(payload)));
    },
    closest: () => null,
    focus() {
      this.focused = true;
    },
  };
}

function runEditor({
  prefilterReason = "Known benign traffic",
  fail = () => false,
  draftResponse = null,
  validateResponse = null,
} = {}) {
  const elements = new Map();
  const calls = [];
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, createElement(id));
      return elements.get(id);
    },
  };
  const summary = {
    mode: "legacy",
    generation: 1,
    writes_enabled: true,
    reload: { consumers: [] },
    active: {
      prefilter_policy: { id: 1 },
      asset_inventory: { id: 2 },
    },
  };
  const prefilter = {
    version: 1,
    internal_cidrs: ["10.0.0.0/24"],
    auto_false_positive: [
      {
        signature_ids: [1001],
        reason: prefilterReason,
        match: { protocols: ["tcp"] },
      },
    ],
  };
  const assets = { version: 1, assets: [] };
  const revision = (id, kind, state = "active") => ({
    id,
    kind,
    revision: `sha256:${String(id).padStart(64, "0")}`,
    source: "operator",
    parent_revision_id: null,
    shipped_base_revision: null,
    state,
    validation: { status: "valid" },
    created_at: "2026-08-15T00:00:00Z",
    created_by: "operator",
    note: null,
  });

  function bodyFor(url, options) {
    const method = options?.method ?? "GET";
    if (url === "/api/v1/config") return summary;
    if (url === "/api/v1/config/prefilter_policy") return { document: prefilter };
    if (url === "/api/v1/config/asset_inventory") return { document: assets };
    if (url === "/api/v1/config/prefilter_policy/revisions?limit=25") {
      return { revisions: [revision(1, "prefilter_policy"), revision(9, "prefilter_policy", "superseded")] };
    }
    if (url === "/api/v1/config/asset_inventory/revisions?limit=25") {
      return { revisions: [revision(2, "asset_inventory")] };
    }
    if (url === "/api/v1/config/audit?limit=25") {
      return { entries: [{ action: "bootstrap_activated", actor: "system", occurred_at: "2026-08-15T00:00:00Z" }] };
    }
    if (url === "/api/v1/config/prefilter_policy/drafts" && method === "POST") {
      return draftResponse ?? { draft: revision(3, "prefilter_policy", "draft"), resumed: false };
    }
    if (url === "/api/v1/config/prefilter_policy/drafts/3/validate" && method === "POST") {
      return validateResponse ?? {
        revision: revision(4, "prefilter_policy", "validated"),
        validation: { status: "valid" },
        candidate_parent_revision_id: 1,
      };
    }
    if (url === "/api/v1/config/prefilter_policy/revisions/4") {
      return { document: { ...prefilter, internal_cidrs: ["10.0.1.0/24"] } };
    }
    if (url === "/api/v1/config/prefilter_policy/drafts/3/preview" && method === "POST") {
      return {
        window_hours: 24,
        candidates_examined: 12,
        truncated: false,
        warnings: [],
        summary: { counts: { newly_suppressed: 1 } },
      };
    }
    if (url === "/api/v1/config/prefilter_policy/drafts/3/activate" && method === "POST") {
      return { generation: 2 };
    }
    if (url === "/api/v1/config/prefilter_policy/drafts/9/preview" && method === "POST") {
      return {
        window_hours: 24,
        candidates_examined: 4,
        truncated: false,
        warnings: [],
        summary: { counts: { newly_suppressed: 0 } },
      };
    }
    if (url === "/api/v1/config/prefilter_policy/revisions/9/rollback" && method === "POST") {
      return { generation: 2 };
    }
    return {};
  }

  const fetch = async (url, options = {}) => {
    const target = String(url);
    calls.push({ url: target, options });
    if (fail(target, options)) {
      return {
        ok: false,
        status: 409,
        json: async () => ({ detail: "configuration generation is stale" }),
      };
    }
    return { ok: true, status: 200, json: async () => bodyFor(target, options) };
  };
  const storageTrap = new Proxy({}, {
    get() {
      throw new Error("persistent storage must not be accessed");
    },
    set() {
      throw new Error("persistent storage must not be accessed");
    },
  });
  const window = {
    document,
    fetch,
    confirm: () => true,
    localStorage: storageTrap,
    sessionStorage: storageTrap,
  };
  const sandbox = { window, document, fetch, Headers, console };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(fs.readFileSync(SCRIPT, "utf8"), sandbox, {
    filename: "configuration.js",
  });
  return { editor: window.TriagewallConfigEditor, document, calls };
}

async function connect(harness, key = "private-config-key") {
  await harness.editor.load();
  harness.document.getElementById("configApiKey").value = key;
  await harness.document.getElementById("configCredentialForm").dispatch("submit");
}

test("keeps the configuration credential only in memory and sends it only as X-API-Key", async () => {
  const harness = runEditor();
  const key = "private-config-key";
  await connect(harness, key);

  assert.equal(harness.editor.state().connected, true);
  assert.equal(harness.document.getElementById("configApiKey").value, "");
  assert.ok(harness.calls.length >= 6);
  for (const call of harness.calls) {
    assert.equal(call.options.headers.get("X-API-Key"), key);
    assert.doesNotMatch(call.url, new RegExp(key));
    assert.doesNotMatch(String(call.options.body ?? ""), new RegExp(key));
  }
  assert.doesNotMatch(harness.document.getElementById("configWorkspace").textContent, new RegExp(key));

  await harness.document.getElementById("configForgetButton").dispatch("click");
  assert.equal(harness.editor.state().connected, false);
});

test("requires draft, validation, bounded preview, and explicit confirmation before activation", async () => {
  const harness = runEditor();
  await connect(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.1.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  assert.equal(harness.document.getElementById("configCreateDraft").disabled, false);

  await harness.document.getElementById("configCreateDraft").dispatch("click");
  await harness.document.getElementById("configValidateDraft").dispatch("click");
  await harness.document.getElementById("configPreviewDraft").dispatch("click");

  assert.equal(harness.editor.state().lifecycle.validatedId, 4);
  assert.equal(harness.document.getElementById("configActivateDraft").disabled, true);
  assert.match(harness.document.getElementById("configPreviewResult").textContent, /newly_suppressed/);
  assert.equal(
    harness.calls.some((call) => call.url.endsWith("/activate")),
    false,
  );

  harness.document.getElementById("configConfirmActivate").checked = true;
  await harness.document.getElementById("configConfirmActivate").dispatch("change");
  assert.equal(harness.document.getElementById("configActivateDraft").disabled, false);
  await harness.document.getElementById("configActivateDraft").dispatch("click");
  assert.equal(
    harness.calls.filter((call) => call.url.endsWith("/activate")).length,
    1,
  );
});

test("drives preview and activation from the submitted draft handle", async () => {
  const harness = runEditor();
  await connect(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.1.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");

  await harness.document.getElementById("configCreateDraft").dispatch("click");
  await harness.document.getElementById("configValidateDraft").dispatch("click");
  await harness.document.getElementById("configPreviewDraft").dispatch("click");
  assert.equal(harness.editor.state().lifecycle.draftId, 3);
  assert.equal(harness.editor.state().lifecycle.validatedId, 4);

  harness.document.getElementById("configConfirmActivate").checked = true;
  await harness.document.getElementById("configConfirmActivate").dispatch("change");
  await harness.document.getElementById("configActivateDraft").dispatch("click");

  for (const suffix of ["/preview", "/activate"]) {
    const call = harness.calls.find((entry) => entry.url.endsWith(suffix));
    assert.ok(call, `expected a ${suffix} call`);
    assert.match(call.url, /\/drafts\/3\//);
  }
});

test("accepts a valid candidate normalized onto an existing immutable revision", async () => {
  const harness = runEditor({
    validateResponse: {
      // Canonicalization reused a superseded revision; the submitted draft
      // still carries the current active parent forward.
      revision: {
        id: 9,
        kind: "prefilter_policy",
        revision: `sha256:${"9".padStart(64, "0")}`,
        source: "operator",
        parent_revision_id: 7,
        shipped_base_revision: null,
        state: "superseded",
        validation: { status: "valid" },
        created_at: "2026-08-15T00:00:00Z",
        created_by: "operator",
        note: null,
      },
      validation: { status: "valid" },
      candidate_parent_revision_id: 1,
    },
  });
  await connect(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.1.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");

  await harness.document.getElementById("configCreateDraft").dispatch("click");
  await harness.document.getElementById("configValidateDraft").dispatch("click");

  assert.equal(harness.editor.state().lifecycle.validatedId, 9);
  assert.doesNotMatch(
    harness.document.getElementById("configLifecycleMessage").textContent,
    /rejected/,
  );
  assert.equal(harness.document.getElementById("configPreviewDraft").disabled, false);

  await harness.document.getElementById("configPreviewDraft").dispatch("click");
  assert.ok(harness.calls.find((entry) => entry.url === "/api/v1/config/prefilter_policy/drafts/3/preview"));
});

test("resumes a validated revision returned for an identical candidate", async () => {
  const harness = runEditor({
    draftResponse: {
      resumed: true,
      draft: {
        id: 9,
        kind: "prefilter_policy",
        revision: `sha256:${"9".padStart(64, "0")}`,
        source: "operator",
        parent_revision_id: 1,
        shipped_base_revision: null,
        state: "validated",
        validation: { status: "valid" },
        created_at: "2026-08-15T00:00:00Z",
        created_by: "operator",
        note: null,
      },
    },
  });
  await connect(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.1.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");

  await harness.document.getElementById("configCreateDraft").dispatch("click");

  assert.deepEqual(
    { ...harness.editor.state().lifecycle, preview: null },
    { kind: "prefilter_policy", draftId: 9, validatedId: 9, preview: null },
  );
  assert.match(harness.document.getElementById("configLifecycleMessage").textContent, /Resumed validated revision #9/);
  assert.equal(harness.document.getElementById("configPreviewDraft").disabled, false);

  await harness.document.getElementById("configPreviewDraft").dispatch("click");

  assert.ok(harness.calls.find((entry) => entry.url === "/api/v1/config/prefilter_policy/drafts/9/preview"));
});

test("a polling load does not replace an already loaded candidate", async () => {
  const harness = runEditor();
  await connect(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.2.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  const callCount = harness.calls.length;

  await harness.editor.load();

  assert.equal(harness.calls.length, callCount);
  assert.equal(harness.editor.state().dirtyKinds.join(","), "prefilter_policy");
  assert.match(harness.document.getElementById("configExactDocument").textContent, /10\.0\.2\.0\/24/);
});

test("alert handoff populates scoped rule and exact-IP asset forms without URL state", async () => {
  const harness = runEditor();
  harness.editor.seedFromAlert({
    signature_id: 2024,
    signature: "Routine TLS alert",
    proto: "TCP",
    direction: "to_server",
    src_port: 51515,
    dest_port: 443,
    src_ip: "10.0.0.8",
    dest_ip: "203.0.113.5",
    asset_context: {
      source: { hostname: "workstation", role: "endpoint", criticality: "medium", internet_facing: false, exposed_ports: [] },
      destination: null,
    },
  }, "prefilter");
  await connect(harness);

  assert.equal(harness.document.getElementById("configRuleSignatures").value, "2024");
  assert.equal(harness.document.getElementById("configRuleProtocol").value, "tcp");
  assert.equal(harness.document.getElementById("configRuleDestinationPorts").value, 443);
  assert.ok(harness.calls.every((call) => !call.url.includes("2024")));

  harness.editor.seedFromAlert({
    src_ip: "10.0.0.8",
    asset_context: { source: { hostname: "workstation", role: "endpoint", criticality: "medium", internet_facing: false, exposed_ports: [] } },
  }, "asset-source");
  assert.equal(harness.document.getElementById("configAssetHostname").value, "workstation");
  assert.equal(harness.document.getElementById("configAssetIps").value, "10.0.0.8");
});

test("escapes operator-controlled rule text before rendering editor lists", async () => {
  const harness = runEditor({ prefilterReason: '<img src=x onerror="alert(1)">' });
  await connect(harness);
  const markup = harness.document.getElementById("configRuleList").innerHTML;
  assert.doesNotMatch(markup, /<img/);
  assert.match(markup, /&lt;img/);
});

test("reports optimistic-lock conflicts without auto-retrying a mutation", async () => {
  const harness = runEditor({ fail: (url) => url.endsWith("/drafts") });
  await connect(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.3.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  await harness.document.getElementById("configCreateDraft").dispatch("click");

  assert.match(harness.document.getElementById("configLifecycleMessage").textContent, /Reload active configuration/);
  assert.equal(harness.calls.filter((call) => call.url.endsWith("/drafts")).length, 1);
});

test("rollback requires an explicit selection and forwards dedicated acknowledgements", async () => {
  const harness = runEditor();
  await connect(harness);
  const rollbackTarget = {
    closest(selector) {
      return selector === "[data-config-rollback]"
        ? { dataset: { configRollback: "9" } }
        : null;
    },
  };

  await harness.document.getElementById("configWorkspace").dispatch("click", { target: rollbackTarget });
  assert.equal(harness.calls.some((call) => call.url.endsWith("/rollback")), false);
  assert.equal(harness.document.getElementById("configRollbackGuard").classList.contains("hidden"), false);
  harness.document.getElementById("configRollbackAcknowledgeBroad").checked = true;
  harness.document.getElementById("configRollbackAcknowledgeBase").checked = true;
  await harness.document.getElementById("configConfirmRollback").dispatch("click");

  const call = harness.calls.find((entry) => entry.url.endsWith("/rollback"));
  assert.ok(call);
  assert.deepEqual(JSON.parse(call.options.body), {
    expected_generation: 1,
    acknowledge_broad_rules: true,
    acknowledge_shipped_base_change: true,
  });
});
