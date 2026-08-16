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
  prefilterRules = null,
  assetRows = [],
  revisionRows = null,
  defer = null,
  confirmReply = () => true,
  draftIds = null,
  previewResponse = null,
  assetRevisionRows = null,
} = {}) {
  const remainingDraftIds = draftIds ? [...draftIds] : null;
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
    auto_false_positive: prefilterRules ?? [
      {
        signature_ids: [1001],
        reason: prefilterReason,
        match: { protocols: ["tcp"] },
      },
    ],
  };
  const assets = { version: 1, assets: assetRows };
  // Independently fetched documents: a test may skew one of them to model a
  // generation that advances between the parallel requests of one load.
  const activeGeneration = {};
  const activeRevisionIds = {};
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
    if (url === "/api/v1/config/prefilter_policy") {
      return {
        generation: activeGeneration.prefilter ?? summary.generation,
        revision: revision(activeRevisionIds.prefilter ?? 1, "prefilter_policy"),
        document: prefilter,
      };
    }
    if (url === "/api/v1/config/asset_inventory") {
      return {
        generation: activeGeneration.assets ?? summary.generation,
        revision: revision(activeRevisionIds.assets ?? 2, "asset_inventory"),
        document: assets,
      };
    }
    if (url === "/api/v1/config/prefilter_policy/revisions?limit=25") {
      return {
        revisions: revisionRows ?? [
          revision(1, "prefilter_policy"),
          revision(9, "prefilter_policy", "superseded"),
        ],
      };
    }
    if (url === "/api/v1/config/prefilter_policy/revisions/9") {
      return {
        generation: summary.generation,
        revision: revision(9, "prefilter_policy", "superseded"),
        document: { version: 1, internal_cidrs: [], auto_false_positive: [] },
      };
    }
    if (url === "/api/v1/config/asset_inventory/revisions?limit=25") {
      return {
        revisions: assetRevisionRows
          ? [revision(2, "asset_inventory"), ...assetRevisionRows]
          : [revision(2, "asset_inventory")],
      };
    }
    const assetRevision = /^\/api\/v1\/config\/asset_inventory\/revisions\/(\d+)$/.exec(url);
    if (assetRevision) {
      return {
        generation: summary.generation,
        revision: revision(Number(assetRevision[1]), "asset_inventory", "superseded"),
        document: { version: 1, assets: [] },
      };
    }
    if (url === "/api/v1/config/audit?limit=25") {
      return { entries: [{ action: "bootstrap_activated", actor: "system", occurred_at: "2026-08-15T00:00:00Z" }] };
    }
    const draftsPost = /^\/api\/v1\/config\/([a-z_]+)\/drafts$/.exec(url);
    if (draftsPost && method === "POST") {
      if (draftResponse) return draftResponse;
      const id = remainingDraftIds?.length ? remainingDraftIds.shift() : 3;
      return { draft: revision(id, draftsPost[1], "draft"), resumed: false };
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
        draft_id: 3,
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
    // Any other draft handle follows the same lifecycle shape, so a test can
    // drive two drafts of the same kind at once.
    const lifecycle = /^\/api\/v1\/config\/([a-z_]+)\/drafts\/(\d+)\/(validate|preview|activate)$/.exec(url);
    if (lifecycle && method === "POST") {
      const id = Number(lifecycle[2]);
      if (lifecycle[3] === "validate") {
        return {
          revision: revision(id + 1, lifecycle[1], "validated"),
          validation: { status: "valid" },
          candidate_parent_revision_id: 1,
        };
      }
      if (lifecycle[3] === "preview") {
        if (previewResponse) return { draft_id: id, ...previewResponse };
        return {
          draft_id: id,
          window_hours: 24,
          candidates_examined: id,
          truncated: false,
          warnings: [],
          summary: { counts: { newly_suppressed: 0 } },
        };
      }
      return { generation: 2 };
    }
    return {};
  }

  const released = [];
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
    // A deferred request only settles when the test releases it, which is how
    // a response is made to arrive after newer state exists.
    if (defer && defer(target, options)) {
      await new Promise((resolve) => released.push(resolve));
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
  const prompts = [];
  const window = {
    document,
    fetch,
    confirm: (message) => {
      prompts.push(String(message));
      return confirmReply(String(message));
    },
    localStorage: storageTrap,
    sessionStorage: storageTrap,
  };
  const sandbox = { window, document, fetch, Headers, console };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(fs.readFileSync(SCRIPT, "utf8"), sandbox, {
    filename: "configuration.js",
  });
  return {
    editor: window.TriagewallConfigEditor,
    document,
    calls,
    prompts,
    summary,
    prefilter,
    assets,
    activeGeneration,
    activeRevisionIds,
    // Drain deferred requests repeatedly: the chain that reaches them may need
    // several ticks to get there, and settling must never depend on ordering.
    async release(ticks = 25) {
      for (let index = 0; index < ticks; index += 1) {
        released.splice(0).forEach((resolve) => resolve());
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    },
  };
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
      validated_revision_id: 9,
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

test("resumes a normalized draft handle directly at preview", async () => {
  const harness = runEditor({
    draftResponse: {
      resumed: true,
      // The submitted draft was normalized onto canonical content, so the
      // handle itself is superseded while its validated result is revision 8.
      validated_revision_id: 8,
      draft: {
        id: 3,
        kind: "prefilter_policy",
        revision: `sha256:${"3".padStart(64, "0")}`,
        source: "operator",
        parent_revision_id: 1,
        shipped_base_revision: null,
        state: "superseded",
        validation: { status: "valid", normalized_revision_id: 8 },
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

  assert.equal(harness.editor.state().lifecycle.draftId, 3);
  assert.equal(harness.editor.state().lifecycle.validatedId, 8);
  assert.equal(harness.document.getElementById("configPreviewDraft").disabled, false);

  await harness.document.getElementById("configPreviewDraft").dispatch("click");

  // Preview and activation stay addressed by the submitted draft handle.
  assert.ok(harness.calls.find((entry) => entry.url === "/api/v1/config/prefilter_policy/drafts/3/preview"));
});

const RICH_RULE = {
  signature_ids: [2019102],
  reason: "Known benign traffic",
  match: {
    protocols: ["tcp", "udp"],
    network_directions: ["internal_to_internal", "internal_to_external"],
    flow_directions: ["to_server", "to_client"],
    source_ports: [443, 8443],
    destination_cidrs: ["10.0.0.0/24"],
    source_asset: { criticalities: ["high"] },
    destination_asset: { internet_facing: true },
  },
};

async function editFirstRule(harness) {
  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-rule-edit]"
          ? { dataset: { configRuleEdit: "0" } }
          : null,
    },
  });
}

function currentRule(harness) {
  return JSON.parse(
    harness.document.getElementById("configExactDocument").textContent,
  ).auto_false_positive[0];
}

test("a reason-only rule edit preserves every constraint the form cannot show", async () => {
  const harness = runEditor({ prefilterRules: [structuredClone(RICH_RULE)] });
  await connect(harness);

  await editFirstRule(harness);
  assert.match(
    harness.document.getElementById("configRulePreserved").textContent,
    /source_asset/,
  );
  harness.document.getElementById("configRuleReason").value = "Reviewed again";
  await harness.document.getElementById("configPrefilterForm").dispatch("submit");

  const applied = currentRule(harness);
  assert.equal(applied.reason, "Reviewed again");
  assert.deepEqual(applied.match, RICH_RULE.match);
  assert.equal(
    JSON.parse(harness.document.getElementById("configExactDocument").textContent)
      .auto_false_positive.length,
    1,
  );
});

test("changing a scoped selector narrows only that constraint", async () => {
  const harness = runEditor({ prefilterRules: [structuredClone(RICH_RULE)] });
  await connect(harness);

  await editFirstRule(harness);
  harness.document.getElementById("configRuleProtocol").value = "udp";
  harness.document.getElementById("configRuleFlowDirection").value = "";
  await harness.document.getElementById("configPrefilterForm").dispatch("submit");

  const applied = currentRule(harness);
  assert.deepEqual(applied.match.protocols, ["udp"]);
  assert.equal(applied.match.flow_directions, undefined);
  assert.deepEqual(
    applied.match.network_directions,
    RICH_RULE.match.network_directions,
  );
  assert.deepEqual(applied.match.source_asset, RICH_RULE.match.source_asset);
  assert.deepEqual(
    applied.match.destination_asset,
    RICH_RULE.match.destination_asset,
  );
  assert.deepEqual(applied.match.source_ports, [443, 8443]);
});

test("rollback confirmation waits for the exact target document", async () => {
  const harness = runEditor();
  await connect(harness);
  const rollbackTarget = {
    closest: (selector) =>
      selector === "[data-config-rollback]"
        ? { dataset: { configRollback: "9" } }
        : null,
  };

  await harness.document.getElementById("configWorkspace").dispatch("click", { target: rollbackTarget });

  assert.ok(harness.calls.find((call) => call.url === "/api/v1/config/prefilter_policy/revisions/9"));
  assert.match(
    harness.document.getElementById("configRollbackDocument").textContent,
    /auto_false_positive/,
  );
  assert.equal(harness.document.getElementById("configConfirmRollback").disabled, false);

  await harness.document.getElementById("configCancelRollback").dispatch("click");
  assert.equal(harness.document.getElementById("configRollbackDocument").textContent, "");
  assert.equal(harness.document.getElementById("configConfirmRollback").disabled, true);
});

test("a rollback target that cannot be fetched is never confirmable", async () => {
  const harness = runEditor({
    fail: (url) => url === "/api/v1/config/prefilter_policy/revisions/9",
  });
  await connect(harness);

  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-rollback]"
          ? { dataset: { configRollback: "9" } }
          : null,
    },
  });

  assert.equal(harness.document.getElementById("configRollbackDocument").textContent, "");
  assert.equal(harness.document.getElementById("configConfirmRollback").disabled, true);
  assert.match(
    harness.document.getElementById("configLifecycleMessage").textContent,
    /could not be loaded/,
  );

  await harness.document.getElementById("configConfirmRollback").dispatch("click");
  assert.equal(harness.calls.some((call) => call.url.endsWith("/rollback")), false);
});

test("normalization inputs are never offered as rollback targets", async () => {
  const harness = runEditor({
    revisionRows: [
      {
        id: 7,
        kind: "prefilter_policy",
        revision: `sha256:${"7".padStart(64, "0")}`,
        source: "operator",
        parent_revision_id: 1,
        shipped_base_revision: null,
        state: "superseded",
        validation: { status: "valid", normalized_revision_id: 8 },
        created_at: "2026-08-15T00:00:00Z",
        created_by: "operator",
        note: null,
      },
    ],
  });
  await connect(harness);

  const markup = harness.document.getElementById("configRevisionList").innerHTML;
  assert.match(markup, /superseded · #7/);
  assert.doesNotMatch(markup, /data-config-rollback/);
});

test("a torn load is never published as an editable candidate", async () => {
  const harness = runEditor();
  // The prefilter document answers from a newer generation than the summary,
  // so the two halves of the snapshot disagree on every attempt.
  harness.activeGeneration.prefilter = 2;
  harness.activeRevisionIds.prefilter = 5;

  await connect(harness);

  assert.equal(harness.editor.state().loaded, false);
  assert.match(
    harness.document.getElementById("configCredentialHelp").textContent,
    /changed while loading/,
  );
  assert.equal(
    harness.calls.filter((call) => call.url === "/api/v1/config").length,
    2,
  );
});

test("a stale load response cannot overwrite an edit, a kind change, or a disconnect", async () => {
  for (const [name, disturb] of [
    ["edit", async (harness) => {
      harness.document.getElementById("configInternalCidrs").value = "10.9.9.0/24";
      await harness.document.getElementById("configInternalCidrs").dispatch("change");
    }],
    ["kind change", async (harness) => {
      await harness.document.getElementById("configWorkspace").dispatch("click", {
        target: {
          closest: (selector) =>
            selector === "[data-config-kind]"
              ? { dataset: { configKind: "asset_inventory" } }
              : null,
        },
      });
    }],
    ["disconnect", async (harness) => {
      await harness.document.getElementById("configForgetButton").dispatch("click");
    }],
  ]) {
    const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
    const connecting = connect(harness);
    await harness.release();
    await connecting;
    assert.equal(harness.editor.state().loaded, true, `${name}: connected`);

    const reload = harness.editor.load(true);
    await disturb(harness);
    const before = harness.editor.state();
    await harness.release();
    await reload;
    const after = harness.editor.state();

    assert.deepEqual(
      { connected: after.connected, dirtyKinds: after.dirtyKinds, selectedKind: after.selectedKind },
      { connected: before.connected, dirtyKinds: before.dirtyKinds, selectedKind: before.selectedKind },
      `${name}: stale response mutated state`,
    );
  }
});

test("a superseded load hands the header status back instead of leaving it loading", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  const connecting = connect(harness);
  await harness.release();
  await connecting;

  const reload = harness.editor.load(true);
  // An edit supersedes the reload, and no newer load exists to own the header.
  harness.document.getElementById("configInternalCidrs").value = "10.9.9.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  await harness.release();
  await reload;

  assert.equal(
    harness.document.getElementById("configConnectionStatus").textContent,
    "Connected for this page only",
  );
  assert.equal(harness.editor.state().loaded, true);
  // The superseded load released the flag it owned, so a later load can run.
  const again = harness.editor.load(true);
  await harness.release();
  await again;
  assert.equal(
    harness.document.getElementById("configConnectionStatus").textContent,
    "Connected for this page only",
  );
});

test("a superseded load leaves a disconnect showing the disconnected status", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  const connecting = connect(harness);
  await harness.release();
  await connecting;

  const reload = harness.editor.load(true);
  await harness.document.getElementById("configForgetButton").dispatch("click");
  await harness.release();
  await reload;

  assert.equal(
    harness.document.getElementById("configConnectionStatus").textContent,
    "Credential required",
  );
  assert.equal(harness.editor.state().connected, false);
});

test("a second credential submission wins and the first publishes nothing", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  await harness.editor.load();

  harness.document.getElementById("configApiKey").value = "key-a";
  const first = harness.document.getElementById("configCredentialForm").dispatch("submit");
  // Key B is submitted while key A's load is still in flight.
  harness.document.getElementById("configApiKey").value = "key-b";
  const second = harness.document.getElementById("configCredentialForm").dispatch("submit");
  await harness.release();
  await Promise.all([first, second]);

  const keysUsed = harness.calls.map((call) => call.options.headers.get("X-API-Key"));
  assert.ok(keysUsed.includes("key-b"), "key B was never attempted");
  // Requests started under key A never carry key B, and vice versa.
  assert.ok(keysUsed.includes("key-a"));
  assert.equal(harness.editor.state().connected, true);
  assert.equal(harness.editor.state().loaded, true);
  assert.equal(
    harness.document.getElementById("configConnectionStatus").textContent,
    "Connected for this page only",
  );
  assert.equal(harness.document.getElementById("configApiKey").value, "");
  // The last load to publish is B's, and only its requests may follow.
  const lastSummaryCall = harness.calls.filter((call) => call.url === "/api/v1/config").pop();
  assert.equal(lastSummaryCall.options.headers.get("X-API-Key"), "key-b");
});

test("a failure from a superseded credential never reports over the newer one", async () => {
  const harness = runEditor({
    defer: (url) => url === "/api/v1/config/audit?limit=25",
    fail: (url, options) => options?.headers?.get("X-API-Key") === "key-a",
  });
  await harness.editor.load();

  harness.document.getElementById("configApiKey").value = "key-a";
  const first = harness.document.getElementById("configCredentialForm").dispatch("submit");
  harness.document.getElementById("configApiKey").value = "key-b";
  const second = harness.document.getElementById("configCredentialForm").dispatch("submit");
  await harness.release();
  await Promise.all([first, second]);

  // Key A's rejection belongs to a credential the operator already replaced.
  assert.equal(harness.editor.state().loaded, true);
  assert.equal(
    harness.document.getElementById("configConnectionStatus").textContent,
    "Connected for this page only",
  );
  assert.doesNotMatch(
    harness.document.getElementById("configCredentialHelp").textContent,
    /stale/,
  );
});

async function connectDeferred(harness) {
  const connecting = connect(harness);
  await harness.release();
  await connecting;
}

async function openRuleEditor(harness) {
  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-rule-edit]"
          ? { dataset: { configRuleEdit: "0" } }
          : null,
    },
  });
}

test("resetting the asset form keeps unfinished rule input through an older reload", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  await connectDeferred(harness);

  const reload = harness.editor.load(true);
  await openRuleEditor(harness);
  harness.document.getElementById("configRuleReason").value = "Half-typed rule";
  await harness.document.getElementById("configRuleReason").dispatch("input");
  // Cancelling the *asset* form must not declare the rule form finished.
  await harness.document.getElementById("configAssetCancel").dispatch("click");
  await harness.release();
  await reload;

  assert.equal(harness.document.getElementById("configRuleReason").value, "Half-typed rule");
  assert.equal(harness.document.getElementById("configRuleIndex").value, "0");
  assert.equal(harness.editor.state().dirtyForms.join(","), "rule");
});

test("resetting the rule form keeps unfinished asset input through an older reload", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  await connectDeferred(harness);

  const reload = harness.editor.load(true);
  harness.document.getElementById("configAssetHostname").value = "half-typed-host";
  await harness.document.getElementById("configAssetHostname").dispatch("input");
  await harness.document.getElementById("configRuleCancel").dispatch("click");
  await harness.release();
  await reload;

  assert.equal(harness.document.getElementById("configAssetHostname").value, "half-typed-host");
  assert.equal(harness.editor.state().dirtyForms.join(","), "asset");
});

test("a change note survives resetting either structured form", async () => {
  for (const cancelId of ["configRuleCancel", "configAssetCancel"]) {
    const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
    await connectDeferred(harness);

    const reload = harness.editor.load(true);
    harness.document.getElementById("configChangeNote").value = "Why this change";
    await harness.document.getElementById("configChangeNote").dispatch("input");
    await harness.document.getElementById(cancelId).dispatch("click");
    await harness.release();
    await reload;

    assert.equal(
      harness.document.getElementById("configChangeNote").value,
      "Why this change",
      `${cancelId}: note discarded`,
    );
    assert.equal(harness.editor.state().dirtyForms.join(","), "note", `${cancelId}: scope`);
  }
});

async function driveDraft(harness, cidr) {
  harness.document.getElementById("configInternalCidrs").value = cidr;
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  await harness.document.getElementById("configCreateDraft").dispatch("click");
  await harness.document.getElementById("configValidateDraft").dispatch("click");
}

test("a stale preview response is never attached to a newer draft", async () => {
  const harness = runEditor({
    draftIds: [3, 13],
    defer: (url) => url.endsWith("/drafts/3/preview"),
  });
  await connect(harness);

  // Draft A: preview starts and stays in flight.
  await driveDraft(harness, "10.0.1.0/24");
  const previewA = harness.document.getElementById("configPreviewDraft").dispatch("click");

  // The operator edits the same kind and drives draft B to validated.
  await driveDraft(harness, "10.0.2.0/24");
  assert.equal(harness.editor.state().lifecycle.draftId, 13);
  assert.equal(harness.editor.state().lifecycle.validatedId, 14);

  // A resolves only now.
  await harness.release();
  await previewA;

  // A's analysis is neither rendered nor attached to B.
  assert.equal(harness.editor.state().lifecycle.preview, null);
  assert.equal(
    harness.document.getElementById("configPreviewResult").textContent,
    "",
  );
  assert.equal(
    harness.document.getElementById("configActivationGuard").classList.contains("hidden"),
    true,
  );

  // B cannot be activated on A's analysis, even with confirmation checked.
  harness.document.getElementById("configConfirmActivate").checked = true;
  await harness.document.getElementById("configConfirmActivate").dispatch("change");
  assert.equal(harness.document.getElementById("configActivateDraft").disabled, true);
  await harness.document.getElementById("configActivateDraft").dispatch("click");
  assert.equal(harness.calls.some((call) => call.url.endsWith("/activate")), false);

  // B's own preview then renders and activates normally.
  await harness.document.getElementById("configPreviewDraft").dispatch("click");
  assert.equal(harness.editor.state().lifecycle.preview.draft_id, 13);
  assert.match(
    harness.document.getElementById("configPreviewResult").textContent,
    /"candidates_examined": 13/,
  );
  harness.document.getElementById("configConfirmActivate").checked = true;
  await harness.document.getElementById("configConfirmActivate").dispatch("change");
  await harness.document.getElementById("configActivateDraft").dispatch("click");
  const activation = harness.calls.filter((call) => call.url.endsWith("/activate"));
  assert.equal(activation.length, 1);
  assert.match(activation[0].url, /\/drafts\/13\/activate$/);
});

test("a stale preview failure cannot overwrite a newer draft's status", async () => {
  const harness = runEditor({
    draftIds: [3, 13],
    defer: (url) => url.endsWith("/drafts/3/preview"),
    fail: (url) => url.endsWith("/drafts/3/preview"),
  });
  await connect(harness);

  await driveDraft(harness, "10.0.1.0/24");
  const previewA = harness.document.getElementById("configPreviewDraft").dispatch("click");
  await driveDraft(harness, "10.0.2.0/24");
  const statusBefore = harness.document.getElementById("configLifecycleMessage").textContent;

  await harness.release();
  await previewA;

  assert.equal(
    harness.document.getElementById("configLifecycleMessage").textContent,
    statusBefore,
  );
  assert.doesNotMatch(
    harness.document.getElementById("configLifecycleMessage").textContent,
    /stale/,
  );
  assert.equal(harness.editor.state().lifecycle.draftId, 13);
});

test("a pending preview is discarded on reload, disconnect, and kind switch", async () => {
  for (const [name, disturb] of [
    ["reload", async (harness) => {
      const reload = harness.editor.load(true);
      await harness.release();
      await reload;
    }],
    ["disconnect", async (harness) => {
      await harness.document.getElementById("configForgetButton").dispatch("click");
    }],
    ["kind switch", async (harness) => {
      await harness.document.getElementById("configWorkspace").dispatch("click", {
        target: {
          closest: (selector) =>
            selector === "[data-config-kind]"
              ? { dataset: { configKind: "asset_inventory" } }
              : null,
        },
      });
    }],
  ]) {
    const harness = runEditor({ defer: (url) => url.endsWith("/drafts/3/preview") });
    await connect(harness);
    await driveDraft(harness, "10.0.1.0/24");
    const preview = harness.document.getElementById("configPreviewDraft").dispatch("click");

    await disturb(harness);
    await harness.release();
    await preview;

    assert.equal(
      harness.editor.state().lifecycle.preview,
      null,
      `${name}: a superseded preview was published`,
    );
    assert.equal(
      harness.document.getElementById("configPreviewResult").textContent,
      "",
      `${name}: a superseded preview was rendered`,
    );
  }
});

test("an incomplete asset preview needs its own acknowledgement to activate", async () => {
  const harness = runEditor({
    assetRows: [
      {
        hostname: "server",
        role: "application",
        ips: ["10.0.0.8"],
        criticality: "low",
        internet_facing: false,
        exposed_ports: [],
      },
    ],
    previewResponse: {
      window_hours: 24,
      candidates_examined: 4,
      truncated: true,
      warnings: ["asset preview could not evaluate every asset-dependent prefilter rule; activation requires acknowledging it"],
      summary: {
        counts: { newly_matched_addresses: 1 },
        suppression: {
          asset_dependent_rule_count: 1,
          complete: false,
          evaluated_candidates: 1,
          unevaluated_candidates: 0,
          counts: { newly_suppressed: 1 },
          affected_event_ids: [7],
          affected_signature_ids: [1001],
        },
      },
    },
  });
  await connect(harness);
  // Work on the asset inventory and dirty its candidate.
  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-asset-remove]"
          ? { dataset: { configAssetRemove: "0" } }
          : null,
    },
  });
  await harness.document.getElementById("configCreateDraft").dispatch("click");
  await harness.document.getElementById("configValidateDraft").dispatch("click");
  await harness.document.getElementById("configPreviewDraft").dispatch("click");

  // The dedicated acknowledgement appears and gates activation on its own.
  assert.equal(
    harness.document.getElementById("configAcknowledgeAssetPreview").classList.contains("hidden"),
    false,
  );
  harness.document.getElementById("configConfirmActivate").checked = true;
  await harness.document.getElementById("configConfirmActivate").dispatch("change");
  assert.equal(harness.document.getElementById("configActivateDraft").disabled, true);
  await harness.document.getElementById("configActivateDraft").dispatch("click");
  assert.equal(harness.calls.some((call) => call.url.endsWith("/activate")), false);

  harness.document.getElementById("configConfirmAssetPreview").checked = true;
  await harness.document.getElementById("configConfirmAssetPreview").dispatch("change");
  assert.equal(harness.document.getElementById("configActivateDraft").disabled, false);
  await harness.document.getElementById("configActivateDraft").dispatch("click");

  const activation = harness.calls.find((call) => call.url.endsWith("/activate"));
  assert.ok(activation);
  assert.equal(
    JSON.parse(activation.options.body).acknowledge_incomplete_asset_preview,
    true,
  );
});

const SEED_ASSET_ROWS = [
  {
    hostname: "server",
    role: "application",
    ips: ["10.0.0.8"],
    criticality: "low",
    internet_facing: false,
    exposed_ports: [],
  },
];

async function typeRuleReason(harness, value) {
  await openRuleEditor(harness);
  harness.document.getElementById("configRuleReason").value = value;
  await harness.document.getElementById("configRuleReason").dispatch("input");
}

async function typeAssetHostname(harness, value) {
  harness.document.getElementById("configAssetHostname").value = value;
  await harness.document.getElementById("configAssetHostname").dispatch("input");
}

test("a declined prefilter handoff preserves the dirty rule form", async () => {
  const harness = runEditor({ confirmReply: () => false });
  await connect(harness);
  await typeRuleReason(harness, "Half-typed reason");
  harness.document.getElementById("configRuleSourcePorts").value = "8443";
  await harness.document.getElementById("configRuleSourcePorts").dispatch("input");

  await harness.editor.seedFromAlert(
    { signature_id: 2024, signature: "Routine TLS alert", proto: "TCP", dest_port: 443 },
    "prefilter",
  );

  assert.equal(harness.prompts.length, 1);
  assert.match(harness.prompts[0], /unapplied rule form input/);
  assert.equal(harness.document.getElementById("configRuleReason").value, "Half-typed reason");
  assert.equal(harness.document.getElementById("configRuleSourcePorts").value, "8443");
  // Still the rule the operator opened, never the alert's signature.
  assert.equal(harness.document.getElementById("configRuleSignatures").value, "1001");
  assert.equal(harness.document.getElementById("configRuleIndex").value, "0");
  assert.equal(harness.editor.state().dirtyForms.join(","), "rule");
  assert.match(
    harness.document.getElementById("configLifecycleMessage").textContent,
    /Kept your unapplied rule form input/,
  );
});

test("an accepted prefilter handoff applies the seed", async () => {
  const harness = runEditor({ confirmReply: () => true });
  await connect(harness);
  await typeRuleReason(harness, "Half-typed reason");

  await harness.editor.seedFromAlert(
    { signature_id: 2024, signature: "Routine TLS alert", proto: "TCP", dest_port: 443 },
    "prefilter",
  );

  assert.equal(harness.prompts.length, 1);
  assert.equal(harness.document.getElementById("configRuleSignatures").value, "2024");
  assert.match(harness.document.getElementById("configRuleReason").value, /Routine TLS alert/);
  assert.equal(harness.editor.state().dirtyForms.join(","), "rule");
});

test("a declined asset handoff preserves the dirty asset form", async () => {
  const harness = runEditor({ confirmReply: () => false, assetRows: SEED_ASSET_ROWS });
  await connect(harness);
  await typeAssetHostname(harness, "half-typed-host");
  harness.document.getElementById("configAssetIps").value = "10.9.9.9";
  await harness.document.getElementById("configAssetIps").dispatch("input");
  const callsBefore = harness.calls.length;

  await harness.editor.seedFromAlert({ src_ip: "203.0.113.7", asset_context: {} }, "asset-source");

  assert.equal(harness.prompts.length, 1);
  assert.match(harness.prompts[0], /unapplied asset form input/);
  assert.equal(harness.document.getElementById("configAssetHostname").value, "half-typed-host");
  assert.equal(harness.document.getElementById("configAssetIps").value, "10.9.9.9");
  assert.equal(harness.editor.state().dirtyForms.join(","), "asset");
  // A declined handoff resolves nothing, so it must not refresh either.
  assert.equal(harness.calls.length, callsBefore);
});

test("an accepted asset handoff applies the seed", async () => {
  const harness = runEditor({ confirmReply: () => true, assetRows: SEED_ASSET_ROWS });
  await connect(harness);
  await typeAssetHostname(harness, "half-typed-host");

  await harness.editor.seedFromAlert({ src_ip: "203.0.113.7", asset_context: {} }, "asset-source");

  assert.equal(harness.prompts.length, 1);
  assert.equal(harness.document.getElementById("configAssetIps").value, "203.0.113.7");
  assert.equal(harness.document.getElementById("configAssetIndex").value, "");
  assert.equal(harness.editor.state().dirtyForms.join(","), "asset");
});

test("a handoff never prompts about an unrelated dirty scope and never erases it", async () => {
  const harness = runEditor({
    confirmReply: () => {
      throw new Error("a handoff must not prompt about an unrelated scope");
    },
    assetRows: SEED_ASSET_ROWS,
  });
  await connect(harness);
  // Dirty: the change note, the CIDR field, and the *other* editor's form.
  harness.document.getElementById("configChangeNote").value = "Why this change";
  await harness.document.getElementById("configChangeNote").dispatch("input");
  harness.document.getElementById("configInternalCidrs").value = "10.7.7.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("input");
  await typeRuleReason(harness, "Half-typed reason");

  await harness.editor.seedFromAlert({ src_ip: "203.0.113.7", asset_context: {} }, "asset-source");

  assert.equal(harness.prompts.length, 0);
  assert.equal(harness.document.getElementById("configAssetIps").value, "203.0.113.7");
  // Every unrelated surface survives untouched.
  assert.equal(harness.document.getElementById("configChangeNote").value, "Why this change");
  assert.equal(harness.document.getElementById("configInternalCidrs").value, "10.7.7.0/24");
  assert.equal(harness.document.getElementById("configRuleReason").value, "Half-typed reason");
  assert.equal(
    harness.editor.state().dirtyForms.slice().sort().join(","),
    "asset,cidrs,note,rule",
  );
});

test("a delayed load cannot overwrite a retained form or an accepted seed", async () => {
  for (const [name, reply, expected] of [
    ["declined", () => false, "Half-typed reason"],
    ["accepted", () => true, "Reviewed false positive: Routine TLS alert"],
  ]) {
    const harness = runEditor({
      confirmReply: reply,
      defer: (url) => url === "/api/v1/config/audit?limit=25",
    });
    await connectDeferred(harness);
    await typeRuleReason(harness, "Half-typed reason");

    const reload = harness.editor.load(true);
    const seeding = harness.editor.seedFromAlert(
      { signature_id: 2024, signature: "Routine TLS alert", proto: "TCP", dest_port: 443 },
      "prefilter",
    );
    await harness.release();
    await Promise.all([reload, seeding]);

    assert.equal(
      harness.document.getElementById("configRuleReason").value,
      expected,
      `${name}: the delayed load overwrote the rule form`,
    );
    assert.equal(harness.editor.state().dirtyForms.join(","), "rule", `${name}: scope`);
  }
});

test("an older reload does not discard an unknown-asset alert seed", async () => {
  const harness = runEditor({
    defer: (url) => url === "/api/v1/config/audit?limit=25",
    assetRows: [
      {
        hostname: "server",
        role: "application",
        ips: ["10.0.0.8"],
        criticality: "low",
        internet_facing: false,
        exposed_ports: [],
      },
    ],
  });
  await connectDeferred(harness);

  const reload = harness.editor.load(true);
  // The seed lands while that reload is still in flight; it supersedes it.
  const seeding = harness.editor.seedFromAlert({ src_ip: "203.0.113.7", asset_context: {} }, "asset-source");
  await harness.release();
  await Promise.all([reload, seeding]);

  assert.equal(harness.document.getElementById("configAssetIps").value, "203.0.113.7");
  assert.equal(harness.document.getElementById("configAssetIndex").value, "");
  assert.equal(harness.editor.state().dirtyForms.join(","), "asset");
});

test("an older reload does not discard a prefilter alert seed", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  await connectDeferred(harness);

  const reload = harness.editor.load(true);
  const seeding = harness.editor.seedFromAlert(
    { signature_id: 2024, signature: "Routine TLS alert", proto: "TCP", dest_port: 443 },
    "prefilter",
  );
  await harness.release();
  await Promise.all([reload, seeding]);

  assert.equal(harness.document.getElementById("configRuleSignatures").value, "2024");
  assert.equal(String(harness.document.getElementById("configRuleDestinationPorts").value), "443");
  assert.equal(harness.editor.state().dirtyForms.join(","), "rule");
});

test("typing an internal CIDR survives an older reload before it commits", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  await connectDeferred(harness);

  const reload = harness.editor.load(true);
  // Keystrokes only: the change event that commits the value has not fired.
  harness.document.getElementById("configInternalCidrs").value = "10.7.7.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("input");
  await harness.release();
  await reload;

  assert.equal(harness.document.getElementById("configInternalCidrs").value, "10.7.7.0/24");
  assert.equal(harness.editor.state().dirtyForms.join(","), "cidrs");
  // The document itself is untouched until the change event commits it.
  assert.equal(harness.editor.state().dirtyKinds.join(","), "");

  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  assert.equal(harness.editor.state().dirtyKinds.join(","), "prefilter_policy");
  assert.equal(harness.editor.state().dirtyForms.join(","), "");
  assert.match(
    harness.document.getElementById("configExactDocument").textContent,
    /10\.7\.7\.0\/24/,
  );
});

test("an older reload does not discard unfinished rule form input", async () => {
  const harness = runEditor({ defer: (url) => url === "/api/v1/config/audit?limit=25" });
  const connecting = connect(harness);
  await harness.release();
  await connecting;

  const reload = harness.editor.load(true);
  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-rule-edit]"
          ? { dataset: { configRuleEdit: "0" } }
          : null,
    },
  });
  harness.document.getElementById("configRuleReason").value = "Half-typed reason";
  await harness.document.getElementById("configRuleReason").dispatch("input");
  harness.document.getElementById("configRuleSourcePorts").value = "8443";
  await harness.document.getElementById("configRuleSourcePorts").dispatch("input");
  await harness.release();
  await reload;

  assert.equal(harness.document.getElementById("configRuleReason").value, "Half-typed reason");
  assert.equal(harness.document.getElementById("configRuleSourcePorts").value, "8443");
  assert.equal(harness.document.getElementById("configRuleIndex").value, "0");
  // Opening and typing in a form is not a document change.
  assert.equal(harness.editor.state().dirtyKinds.join(","), "");
});

test("an older reload does not discard unfinished asset form input", async () => {
  const harness = runEditor({
    defer: (url) => url === "/api/v1/config/audit?limit=25",
    assetRows: [
      {
        hostname: "server",
        role: "application",
        ips: ["10.0.0.8"],
        criticality: "low",
        internet_facing: false,
        exposed_ports: [],
      },
    ],
  });
  const connecting = connect(harness);
  await harness.release();
  await connecting;

  const reload = harness.editor.load(true);
  harness.document.getElementById("configAssetHostname").value = "new-host";
  await harness.document.getElementById("configAssetHostname").dispatch("input");
  harness.document.getElementById("configAssetCriticality").value = "critical";
  await harness.document.getElementById("configAssetCriticality").dispatch("change");
  harness.document.getElementById("configAssetInternetFacing").checked = true;
  await harness.document.getElementById("configAssetInternetFacing").dispatch("change");
  harness.document.getElementById("configAssetIps").value = "10.0.0.8, 10.0.0.9";
  await harness.document.getElementById("configAssetIps").dispatch("input");
  await harness.release();
  await reload;

  assert.equal(harness.document.getElementById("configAssetHostname").value, "new-host");
  assert.equal(harness.document.getElementById("configAssetCriticality").value, "critical");
  assert.equal(harness.document.getElementById("configAssetInternetFacing").checked, true);
  assert.equal(harness.document.getElementById("configAssetIps").value, "10.0.0.8, 10.0.0.9");
  assert.equal(harness.editor.state().dirtyKinds.join(","), "");
});

test("cancelling an edited form restores the add-mode editor state", async () => {
  const harness = runEditor({ prefilterRules: [structuredClone(RICH_RULE)] });
  await connect(harness);

  await editFirstRule(harness);
  harness.document.getElementById("configRuleReason").value = "Half-typed reason";
  await harness.document.getElementById("configRuleReason").dispatch("input");
  await harness.document.getElementById("configRuleCancel").dispatch("click");

  assert.equal(harness.document.getElementById("configRuleReason").value, "");
  assert.equal(harness.document.getElementById("configRuleIndex").value, "");
  assert.equal(harness.document.getElementById("configRuleFormTitle").textContent, "Add scoped rule");
  assert.equal(harness.document.getElementById("configRulePreserved").textContent, "");
  assert.equal(harness.editor.state().dirtyKinds.join(","), "");
});

test("an explicitly confirmed reload discards unfinished form input", async () => {
  const harness = runEditor();
  await connect(harness);

  await editFirstRule(harness);
  harness.document.getElementById("configRuleReason").value = "Half-typed reason";
  await harness.document.getElementById("configRuleReason").dispatch("input");
  await harness.document.getElementById("configReloadButton").dispatch("click");

  // window.confirm answers true in this harness, so the operator accepted it.
  assert.equal(harness.document.getElementById("configRuleReason").value, "");
  assert.equal(harness.document.getElementById("configRuleIndex").value, "");
});

test("alert handoff refreshes before deciding add versus edit", async () => {
  const harness = runEditor();
  await connect(harness);
  // The address is added to the active inventory after this editor cached it.
  harness.summary.generation = 2;
  harness.activeGeneration.prefilter = 2;
  harness.activeGeneration.assets = 2;
  harness.assets.assets.push({
    hostname: "late-server",
    role: "application",
    ips: ["10.0.0.42", "10.0.0.43"],
    criticality: "high",
    internet_facing: false,
    exposed_ports: [{ protocol: "tcp", port: 8443 }],
  });

  await harness.editor.seedFromAlert({ src_ip: "10.0.0.43", asset_context: {} }, "asset-source");

  assert.equal(harness.editor.state().generation, 2);
  assert.equal(harness.document.getElementById("configAssetIndex").value, "0");
  assert.equal(harness.document.getElementById("configAssetHostname").value, "late-server");
  assert.equal(harness.document.getElementById("configAssetIps").value, "10.0.0.42, 10.0.0.43");
  assert.equal(harness.document.getElementById("configAssetPorts").value, "tcp/8443");
});

test("alert handoff never silently discards a dirty asset candidate", async () => {
  const harness = runEditor({
    assetRows: [
      {
        hostname: "server",
        role: "application",
        ips: ["10.0.0.8"],
        criticality: "low",
        internet_facing: false,
        exposed_ports: [],
      },
    ],
  });
  await connect(harness);
  // A local, unactivated asset change is present.
  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-asset-remove]"
          ? { dataset: { configAssetRemove: "0" } }
          : null,
    },
  });
  assert.equal(harness.editor.state().dirtyKinds.join(","), "asset_inventory");
  const callsBefore = harness.calls.length;

  await harness.editor.seedFromAlert({ src_ip: "10.0.0.8", asset_context: {} }, "asset-source");

  // No refresh was issued, so the candidate survives, and the operator is told
  // the decision used their possibly older local candidate.
  assert.equal(harness.calls.length, callsBefore);
  assert.equal(harness.editor.state().dirtyKinds.join(","), "asset_inventory");
  assert.equal(
    JSON.parse(harness.document.getElementById("configExactDocument").textContent).assets.length,
    0,
  );
  assert.match(
    harness.document.getElementById("configLifecycleMessage").textContent,
    /may be older than the active configuration/,
  );
});

test("alert handoff edits the existing asset that already owns the address", async () => {
  const harness = runEditor({
    assetRows: [
      {
        hostname: "server",
        role: "application",
        ips: ["10.0.0.8", "10.0.0.9", "fe80::1"],
        criticality: "high",
        internet_facing: true,
        exposed_ports: [{ protocol: "tcp", port: 443 }],
      },
    ],
  });
  await connect(harness);

  await harness.editor.seedFromAlert({ src_ip: "10.0.0.9", asset_context: {} }, "asset-source");

  assert.equal(harness.document.getElementById("configAssetIndex").value, "0");
  assert.equal(harness.document.getElementById("configAssetHostname").value, "server");
  assert.equal(harness.document.getElementById("configAssetIps").value, "10.0.0.8, 10.0.0.9, fe80::1");
  assert.equal(harness.document.getElementById("configAssetCriticality").value, "high");
  assert.equal(harness.document.getElementById("configAssetInternetFacing").checked, true);
  assert.equal(harness.document.getElementById("configAssetPorts").value, "tcp/443");

  await harness.document.getElementById("configAssetForm").dispatch("submit");

  const inventory = JSON.parse(
    harness.document.getElementById("configExactDocument").textContent,
  );
  assert.equal(inventory.assets.length, 1);
  assert.deepEqual(inventory.assets[0].ips, ["10.0.0.8", "10.0.0.9", "fe80::1"]);
});

test("an unknown alert address still opens the asset form in add mode", async () => {
  const harness = runEditor({
    assetRows: [
      {
        hostname: "server",
        role: "application",
        ips: ["10.0.0.8"],
        criticality: "high",
        internet_facing: false,
        exposed_ports: [],
      },
    ],
  });
  await connect(harness);

  await harness.editor.seedFromAlert({ src_ip: "203.0.113.7", asset_context: {} }, "asset-source");

  assert.equal(harness.document.getElementById("configAssetIndex").value, "");
  assert.equal(harness.document.getElementById("configAssetIps").value, "203.0.113.7");
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

  await harness.editor.seedFromAlert({
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

async function beginDraft(harness, cidr = "10.0.1.0/24") {
  harness.document.getElementById("configInternalCidrs").value = cidr;
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  await harness.document.getElementById("configCreateDraft").dispatch("click");
}

// Returns the pending validation without awaiting it, so a test can disturb
// the lifecycle while the request is still in flight.
function startValidation(harness) {
  return harness.document.getElementById("configValidateDraft").dispatch("click");
}

test("a stale validation response cannot overwrite a newer candidate", async () => {
  const harness = runEditor({ defer: (url) => url.endsWith("/drafts/3/validate") });
  await connect(harness);
  await beginDraft(harness);
  const validation = startValidation(harness);

  // The operator keeps editing the same kind while validation is in flight.
  harness.document.getElementById("configInternalCidrs").value = "10.0.9.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  await harness.release();
  await validation;

  assert.equal(harness.editor.state().lifecycle.validatedId, null);
  assert.equal(harness.editor.state().lifecycle.draftId, null);
  assert.equal(harness.editor.state().dirtyKinds.join(","), "prefilter_policy");
  assert.match(
    harness.document.getElementById("configExactDocument").textContent,
    /10\.0\.9\.0\/24/,
  );
  // The canonical document of the superseded draft is never requested.
  assert.equal(
    harness.calls.some((call) => call.url.includes("/revisions/4")),
    false,
  );
});

test("a validation superseded by a kind switch fetches no canonical revision", async () => {
  const harness = runEditor({ defer: (url) => url.endsWith("/drafts/3/validate") });
  await connect(harness);
  await beginDraft(harness);
  const validation = startValidation(harness);

  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-kind]"
          ? { dataset: { configKind: "asset_inventory" } }
          : null,
    },
  });
  await harness.release();
  await validation;

  assert.equal(harness.editor.state().selectedKind, "asset_inventory");
  assert.equal(harness.editor.state().lifecycle.validatedId, null);
  // Neither kind's revision endpoint is asked for the canonical document.
  assert.equal(
    harness.calls.some((call) => /\/revisions\/4$/.test(call.url)),
    false,
  );
});

test("a stale canonical revision response cannot replace newer work", async () => {
  const harness = runEditor({ defer: (url) => /\/revisions\/4$/.test(url) });
  await connect(harness);
  await beginDraft(harness);
  const validation = startValidation(harness);
  // Validation resolved; its canonical fetch is the request still in flight.
  harness.document.getElementById("configInternalCidrs").value = "10.0.9.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  await harness.release();
  await validation;

  assert.equal(harness.editor.state().lifecycle.validatedId, null);
  assert.match(
    harness.document.getElementById("configExactDocument").textContent,
    /10\.0\.9\.0\/24/,
  );
});

test("reload and disconnect invalidate a pending validation", async () => {
  for (const [name, disturb, expectConnected] of [
    ["reload", async (harness) => {
      const reload = harness.editor.load(true);
      await harness.release();
      await reload;
    }, true],
    ["disconnect", async (harness) => {
      await harness.document.getElementById("configForgetButton").dispatch("click");
    }, false],
  ]) {
    const harness = runEditor({ defer: (url) => url.endsWith("/drafts/3/validate") });
    await connect(harness);
    await beginDraft(harness);
  const validation = startValidation(harness);

    await disturb(harness);
    await harness.release();
    await validation;

    assert.equal(
      harness.editor.state().lifecycle.validatedId,
      null,
      `${name}: a superseded validation published`,
    );
    assert.equal(harness.editor.state().connected, expectConnected, `${name}: session`);
  }
});

test("a stale validation failure cannot replace newer status", async () => {
  const harness = runEditor({
    defer: (url) => url.endsWith("/drafts/3/validate"),
    fail: (url) => url.endsWith("/drafts/3/validate"),
  });
  await connect(harness);
  await beginDraft(harness);
  const validation = startValidation(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.9.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  const statusBefore = harness.document.getElementById("configLifecycleMessage").textContent;

  await harness.release();
  await validation;

  assert.equal(
    harness.document.getElementById("configLifecycleMessage").textContent,
    statusBefore,
  );
});

test("a stale canonical-fetch failure cannot replace newer status", async () => {
  const harness = runEditor({
    defer: (url) => /\/revisions\/4$/.test(url),
    fail: (url) => /\/revisions\/4$/.test(url),
  });
  await connect(harness);
  await beginDraft(harness);
  const validation = startValidation(harness);
  harness.document.getElementById("configInternalCidrs").value = "10.0.9.0/24";
  await harness.document.getElementById("configInternalCidrs").dispatch("change");
  const statusBefore = harness.document.getElementById("configLifecycleMessage").textContent;

  await harness.release();
  await validation;

  assert.equal(
    harness.document.getElementById("configLifecycleMessage").textContent,
    statusBefore,
  );
});

test("a current validation publishes through the correct kind and proceeds", async () => {
  const harness = runEditor();
  await connect(harness);
  await beginDraft(harness);
  await startValidation(harness);

  const canonical = harness.calls.find((call) => /\/revisions\/4$/.test(call.url));
  assert.ok(canonical);
  assert.match(canonical.url, /\/prefilter_policy\/revisions\/4$/);
  assert.equal(harness.editor.state().lifecycle.validatedId, 4);
  assert.match(
    harness.document.getElementById("configExactDocument").textContent,
    /10\.0\.1\.0\/24/,
  );

  await harness.document.getElementById("configPreviewDraft").dispatch("click");
  harness.document.getElementById("configConfirmActivate").checked = true;
  await harness.document.getElementById("configConfirmActivate").dispatch("change");
  await harness.document.getElementById("configActivateDraft").dispatch("click");
  assert.equal(
    harness.calls.filter((call) => call.url.endsWith("/activate")).length,
    1,
  );
});

const ASSET_ROLLBACK_ROWS = [
  {
    id: 21,
    kind: "asset_inventory",
    revision: `sha256:${"21".padStart(64, "0")}`,
    source: "operator",
    parent_revision_id: 2,
    shipped_base_revision: null,
    state: "superseded",
    validation: { status: "valid" },
    created_at: "2026-08-16T00:00:00Z",
    created_by: "operator",
    note: null,
  },
];

function rollbackClick(id) {
  return {
    target: {
      closest: (selector) =>
        selector === "[data-config-rollback]"
          ? { dataset: { configRollback: String(id) } }
          : null,
    },
  };
}

async function selectAssetRollback(harness, id = 21) {
  await harness.document.getElementById("configWorkspace").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-config-kind]"
          ? { dataset: { configKind: "asset_inventory" } }
          : null,
    },
  });
  await harness.document.getElementById("configWorkspace").dispatch("click", rollbackClick(id));
}

test("an asset rollback requires its own acknowledgement before confirming", async () => {
  const harness = runEditor({ assetRevisionRows: ASSET_ROLLBACK_ROWS });
  await connect(harness);

  await selectAssetRollback(harness);

  // The dedicated control appears once the exact target document is on screen.
  assert.match(
    harness.document.getElementById("configRollbackDocument").textContent,
    /assets/,
  );
  assert.equal(
    harness.document.getElementById("configRollbackAssetGuard").classList.contains("hidden"),
    false,
  );
  assert.equal(harness.document.getElementById("configConfirmRollback").disabled, true);

  // A forced click before acknowledgement sends nothing.
  await harness.document.getElementById("configConfirmRollback").dispatch("click");
  assert.equal(harness.calls.some((call) => call.url.endsWith("/rollback")), false);
  assert.match(
    harness.document.getElementById("configLifecycleMessage").textContent,
    /Acknowledge the rollback conditions/,
  );

  harness.document.getElementById("configConfirmRollbackAssetPreview").checked = true;
  await harness.document.getElementById("configConfirmRollbackAssetPreview").dispatch("change");
  assert.equal(harness.document.getElementById("configConfirmRollback").disabled, false);
  await harness.document.getElementById("configConfirmRollback").dispatch("click");

  const call = harness.calls.find((entry) => entry.url.endsWith("/rollback"));
  assert.ok(call);
  assert.match(call.url, /\/asset_inventory\/revisions\/21\/rollback$/);
  assert.deepEqual(JSON.parse(call.options.body), {
    expected_generation: 1,
    acknowledge_broad_rules: false,
    acknowledge_shipped_base_change: false,
    acknowledge_incomplete_asset_preview: true,
  });
});

test("an asset rollback acknowledgement never survives a change of context", async () => {
  for (const [name, disturb] of [
    ["cancel", async (harness) => {
      await harness.document.getElementById("configCancelRollback").dispatch("click");
      await selectAssetRollback(harness);
    }],
    ["another target", async (harness) => {
      await harness.document.getElementById("configWorkspace").dispatch("click", rollbackClick(21));
    }],
    ["reload", async (harness) => {
      await harness.editor.load(true);
      await selectAssetRollback(harness);
    }],
    ["kind switch", async (harness) => {
      await harness.document.getElementById("configWorkspace").dispatch("click", {
        target: {
          closest: (selector) =>
            selector === "[data-config-kind]"
              ? { dataset: { configKind: "prefilter_policy" } }
              : null,
        },
      });
      await selectAssetRollback(harness);
    }],
  ]) {
    const harness = runEditor({ assetRevisionRows: ASSET_ROLLBACK_ROWS });
    await connect(harness);
    await selectAssetRollback(harness);
    harness.document.getElementById("configConfirmRollbackAssetPreview").checked = true;
    await harness.document.getElementById("configConfirmRollbackAssetPreview").dispatch("change");

    await disturb(harness);

    assert.equal(
      harness.document.getElementById("configConfirmRollbackAssetPreview").checked,
      false,
      `${name}: the acknowledgement survived`,
    );
    assert.equal(
      harness.document.getElementById("configConfirmRollback").disabled,
      true,
      `${name}: confirmation stayed enabled`,
    );
  }
});

test("a disconnect clears the asset rollback acknowledgement", async () => {
  const harness = runEditor({ assetRevisionRows: ASSET_ROLLBACK_ROWS });
  await connect(harness);
  await selectAssetRollback(harness);
  harness.document.getElementById("configConfirmRollbackAssetPreview").checked = true;
  await harness.document.getElementById("configConfirmRollbackAssetPreview").dispatch("change");

  await harness.document.getElementById("configForgetButton").dispatch("click");

  assert.equal(harness.editor.state().connected, false);
  assert.equal(
    harness.document.getElementById("configConfirmRollbackAssetPreview").checked,
    false,
  );
});

test("activation and rollback acknowledgements are independent", async () => {
  const harness = runEditor({ assetRevisionRows: ASSET_ROLLBACK_ROWS });
  await connect(harness);
  await selectAssetRollback(harness);
  harness.document.getElementById("configConfirmRollbackAssetPreview").checked = true;
  await harness.document.getElementById("configConfirmRollbackAssetPreview").dispatch("change");

  // Checking the rollback acknowledgement never satisfies the activation one.
  assert.equal(
    harness.document.getElementById("configConfirmAssetPreview").checked,
    false,
  );
  harness.document.getElementById("configConfirmAssetPreview").checked = true;
  await harness.document.getElementById("configCancelRollback").dispatch("click");
  // Cancelling a rollback never clears activation state either.
  assert.equal(
    harness.document.getElementById("configConfirmAssetPreview").checked,
    true,
  );
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
    // A prefilter rollback never asserts an asset acknowledgement it was not
    // asked for, and its control stays hidden.
    acknowledge_incomplete_asset_preview: false,
  });
  assert.equal(
    harness.document.getElementById("configRollbackAssetGuard").classList.contains("hidden"),
    true,
  );
});
