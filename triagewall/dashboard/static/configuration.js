(function installConfigurationEditor(global) {
  "use strict";

  const KINDS = ["prefilter_policy", "asset_inventory"];
  const MAX_SNAPSHOT_ATTEMPTS = 2;
  const CREDENTIAL_HELP = "The key must carry config:write. It is kept only in this page's memory and is cleared on reload or disconnect.";
  let apiKey = "";
  let initialized = false;
  let loaded = false;
  let loading = false;
  // Which load currently owns the `loading` flag and the header status.
  let loadingEpoch = null;
  let summary = null;
  let selectedKind = "prefilter_policy";
  let activeDocuments = {};
  let workingDocuments = {};
  let revisions = {};
  let auditEntries = [];
  let dirtyKinds = new Set();
  let lifecycle = emptyLifecycle();
  let pendingRollbackId = null;
  let rollbackTarget = null;
  let pendingSeed = null;
  let editingRule = null;
  let editingRuleForm = null;
  // Which editor surfaces hold unapplied input. Tracked per surface, because
  // resetting one form must not declare the operator's work in another form --
  // or in the change note -- finished. None of these is a document change; each
  // is operator work that a background reload must not discard.
  const FORM_SCOPES = { rule: "rule", asset: "asset", note: "note", cidrs: "cidrs" };
  let dirtyForms = new Set();
  // Monotonic epoch for everything an in-flight response could overwrite. A
  // response may only publish when the epoch it started under is still current,
  // so a slow reload can never resurrect stale bytes over a newer load, a local
  // edit, a kind change, or a disconnect.
  let stateEpoch = 0;

  function emptyLifecycle() {
    return { kind: null, draftId: null, validatedId: null, preview: null };
  }

  function invalidateInFlightResponses() {
    stateEpoch += 1;
    return stateEpoch;
  }

  function noteFormActivity(scope) {
    // Opening, typing in, or programmatically populating an editor surface is
    // newer state than any reload already in flight, so that reload may no
    // longer reset these fields. This deliberately does not mark the candidate
    // document dirty: unapplied form input has not changed the document yet.
    dirtyForms.add(scope);
    invalidateInFlightResponses();
  }

  function clearFormScope(scope) {
    dirtyForms.delete(scope);
  }

  function hasUnappliedFormWork() {
    return dirtyForms.size > 0;
  }

  function element(id) {
    return global.document.getElementById(id);
  }

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character]);
  }

  function labelKind(kind) {
    return kind === "prefilter_policy" ? "Prefilter policy" : "Asset inventory";
  }

  function setConnectionStatus(message, tone = "") {
    const host = element("configConnectionStatus");
    host.textContent = message;
    host.className = `view-status ${tone}`.trim();
  }

  function setMessage(message, isError = false) {
    const host = element("configLifecycleMessage");
    host.textContent = message;
    host.classList.toggle("error", isError);
  }

  async function configRequest(path, options = {}, credential = apiKey) {
    // The credential is passed per request, never read from a mutable global at
    // send time: a load that started under one key must never send another.
    if (!credential) throw new Error("Enter a configuration API key first.");
    const headers = new Headers(options.headers || {});
    headers.set("X-API-Key", credential);
    if (options.body != null) headers.set("Content-Type", "application/json");
    const response = await global.fetch(path, {
      ...options,
      headers,
      cache: "no-store",
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }
    if (!response.ok) {
      const detail = typeof payload?.detail === "string"
        ? payload.detail
        : `Configuration request failed (${response.status}).`;
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function csvStrings(value) {
    return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
  }

  function csvIntegers(value, label) {
    return csvStrings(value).map((item) => {
      if (!/^\d+$/.test(item)) throw new Error(`${label} must contain integers only.`);
      const parsed = Number(item);
      if (!Number.isSafeInteger(parsed)) throw new Error(`${label} contains an invalid integer.`);
      return parsed;
    });
  }

  function renderConnection(connected) {
    element("configCredentialPanel").classList.toggle("hidden", connected);
    element("configWorkspace").classList.toggle("hidden", !connected);
    setConnectionStatus(connected ? "Connected for this page only" : "Credential required", connected ? "ok" : "");
  }

  function renderSummary() {
    element("configMode").textContent = summary?.mode ?? "—";
    element("configGeneration").textContent = summary?.generation ?? "—";
    element("configWrites").textContent = summary?.writes_enabled ? "Enabled" : "Read only";
    const consumers = summary?.reload?.consumers ?? [];
    if (!consumers.length) {
      element("configConsumers").textContent = "Not observed";
    } else {
      const healthy = consumers.filter((consumer) =>
        consumer.status === "ok" && consumer.loaded_generation === summary.generation
      ).length;
      element("configConsumers").textContent = `${healthy}/${consumers.length} current`;
      element("configConsumers").title = consumers.map((consumer) =>
        `${consumer.consumer}: ${consumer.status}, loaded ${consumer.loaded_generation}, desired ${summary.generation}`
      ).join("\n");
    }
  }

  const RULE_SELECT_FIELDS = [
    ["protocols", "configRuleProtocol"],
    ["network_directions", "configRuleNetworkDirection"],
    ["flow_directions", "configRuleFlowDirection"],
  ];
  const RULE_NUMBER_LIST_FIELDS = [
    ["source_ports", "configRuleSourcePorts", "Source ports"],
    ["destination_ports", "configRuleDestinationPorts", "Destination ports"],
  ];
  const RULE_TEXT_LIST_FIELDS = [
    ["source_cidrs", "configRuleSourceCidrs"],
    ["destination_cidrs", "configRuleDestinationCidrs"],
  ];
  // Every control whose unapplied input a background reload must not discard.
  const RULE_FORM_INPUT_IDS = [
    "configRuleSignatures",
    "configRuleReason",
    "configRuleProtocol",
    "configRuleNetworkDirection",
    "configRuleFlowDirection",
    "configRuleSourcePorts",
    "configRuleDestinationPorts",
    "configRuleSourceCidrs",
    "configRuleDestinationCidrs",
  ];
  const ASSET_FORM_INPUT_IDS = [
    "configAssetHostname",
    "configAssetRole",
    "configAssetIps",
    "configAssetCriticality",
    "configAssetInternetFacing",
    "configAssetPorts",
  ];
  // The change note belongs to neither structured form: resetting either one
  // must leave a half-written note alone.
  const NOTE_FORM_INPUT_IDS = ["configChangeNote"];
  const RULE_FORM_MATCH_KEYS = [
    ...RULE_SELECT_FIELDS.map(([key]) => key),
    ...RULE_NUMBER_LIST_FIELDS.map(([key]) => key),
    ...RULE_TEXT_LIST_FIELDS.map(([key]) => key),
  ];

  function resetRuleForm() {
    editingRule = null;
    editingRuleForm = null;
    // Only this form's work is finished; the asset form and the change note
    // keep whatever unapplied input they hold.
    clearFormScope(FORM_SCOPES.rule);
    element("configRuleIndex").value = "";
    element("configRuleSignatures").value = "";
    element("configRuleReason").value = "";
    element("configRuleProtocol").value = "";
    element("configRuleNetworkDirection").value = "";
    element("configRuleFlowDirection").value = "";
    element("configRuleSourcePorts").value = "";
    element("configRuleDestinationPorts").value = "";
    element("configRuleSourceCidrs").value = "";
    element("configRuleDestinationCidrs").value = "";
    element("configRuleFormTitle").textContent = "Add scoped rule";
    element("configRuleCancel").classList.add("hidden");
    element("configRulePreserved").textContent = "";
  }

  function cancelRuleForm() {
    // Cancelling is a deliberate action on this form only. It is newer than any
    // reload in flight, which must therefore not go on to reset the asset form
    // or the change note on this operator's behalf.
    invalidateInFlightResponses();
    resetRuleForm();
  }

  function cancelAssetForm() {
    invalidateInFlightResponses();
    resetAssetForm();
  }

  function describePreservedConstraints(rule) {
    const match = rule?.match ?? {};
    const notes = Object.keys(match).sort().filter((key) => {
      if (!RULE_FORM_MATCH_KEYS.includes(key)) return true;
      const value = match[key];
      return Array.isArray(value) && value.length > 1;
    }).map((key) => `${key}: ${JSON.stringify(match[key])}`);
    return notes.length
      ? `Preserved as-is (not editable in this form): ${notes.join(" · ")}`
      : "";
  }

  function resetAssetForm() {
    clearFormScope(FORM_SCOPES.asset);
    element("configAssetIndex").value = "";
    element("configAssetHostname").value = "";
    element("configAssetRole").value = "";
    element("configAssetIps").value = "";
    element("configAssetCriticality").value = "low";
    element("configAssetInternetFacing").checked = false;
    element("configAssetPorts").value = "";
    element("configAssetFormTitle").textContent = "Add asset";
    element("configAssetCancel").classList.add("hidden");
  }

  function renderPrefilter() {
    const document = workingDocuments.prefilter_policy ?? { version: 1, internal_cidrs: [], auto_false_positive: [] };
    const rules = Array.isArray(document.auto_false_positive) ? document.auto_false_positive : [];
    // Re-rendering the editor must not retype this field under the operator.
    // While it holds uncommitted keystrokes it belongs to them, not to the
    // document being rendered.
    if (!dirtyForms.has(FORM_SCOPES.cidrs)) {
      element("configInternalCidrs").value = (document.internal_cidrs ?? []).join(", ");
    }
    element("configRuleCount").textContent = `${rules.length} rule${rules.length === 1 ? "" : "s"}`;
    element("configRuleList").innerHTML = rules.length ? rules.map((rule, index) => {
      const scope = rule.match && Object.keys(rule.match).length
        ? Object.entries(rule.match).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join(" · ")
        : "Unscoped signature-only rule";
      return `<article class="config-item">
        <div><strong>SID ${escapeHtml((rule.signature_ids ?? []).join(", "))}</strong><p>${escapeHtml(rule.reason ?? "")}</p><small>${escapeHtml(scope)}</small></div>
        <div><button class="text-button" type="button" data-config-rule-edit="${index}">Edit</button><button class="text-button danger" type="button" data-config-rule-remove="${index}">Remove</button></div>
      </article>`;
    }).join("") : '<p class="detail-empty">No deterministic false-positive rules.</p>';
  }

  function renderAssets() {
    const document = workingDocuments.asset_inventory ?? { version: 1, assets: [] };
    const assets = Array.isArray(document.assets) ? document.assets : [];
    element("configAssetCount").textContent = `${assets.length} asset${assets.length === 1 ? "" : "s"}`;
    element("configAssetList").innerHTML = assets.length ? assets.map((asset, index) => {
      const ports = (asset.exposed_ports ?? []).map((port) => `${port.protocol}/${port.port}`).join(", ") || "no exposed ports";
      return `<article class="config-item">
        <div><strong>${escapeHtml(asset.hostname)}</strong><p>${escapeHtml((asset.ips ?? []).join(", "))}</p><small>${escapeHtml(asset.role)} · ${escapeHtml(asset.criticality)} · ${asset.internet_facing ? "internet facing" : "internal"} · ${escapeHtml(ports)}</small></div>
        <div><button class="text-button" type="button" data-config-asset-edit="${index}">Edit</button><button class="text-button danger" type="button" data-config-asset-remove="${index}">Remove</button></div>
      </article>`;
    }).join("") : '<p class="detail-empty">No private assets recorded.</p>';
  }

  function renderExactDocument() {
    const document = workingDocuments[selectedKind];
    element("configExactDocument").textContent = document ? JSON.stringify(document, null, 2) : "";
    const dirty = dirtyKinds.has(selectedKind);
    element("configDirtyState").textContent = dirty ? "Candidate differs from active" : "Active document";
  }

  function renderLifecycle() {
    const writesEnabled = Boolean(summary?.writes_enabled);
    const ownsKind = lifecycle.kind === selectedKind;
    element("configCreateDraft").disabled = !writesEnabled || !workingDocuments[selectedKind] || !dirtyKinds.has(selectedKind);
    element("configValidateDraft").disabled = !writesEnabled || !ownsKind || !lifecycle.draftId;
    element("configPreviewDraft").disabled = !writesEnabled || !ownsKind || !lifecycle.validatedId;
    const hasPreview = ownsKind && lifecycle.preview;
    element("configActivationGuard").classList.toggle("hidden", !hasPreview);
    // An asset preview that could not evaluate every asset-scoped prefilter
    // rule is incomplete evidence, so activation needs that stated explicitly.
    const incompleteAssetPreview = Boolean(
      hasPreview && lifecycle.preview.summary?.suppression?.complete === false
    );
    element("configAcknowledgeAssetPreview").classList.toggle(
      "hidden",
      !incompleteAssetPreview,
    );
    element("configActivateDraft").disabled = !hasPreview
      || !element("configConfirmActivate").checked
      || (incompleteAssetPreview && !element("configConfirmAssetPreview").checked);
    if (!hasPreview) {
      element("configPreviewResult").classList.add("hidden");
      element("configPreviewResult").textContent = "";
    }
  }

  function isRollbackTarget(revision) {
    // A superseded row is not necessarily a previously active revision: a draft
    // that validation normalized keeps the operator's pre-canonical bytes and
    // records the canonical revision it produced. It was never active, so it is
    // never offered as a rollback target.
    return revision.state === "superseded"
      && revision.validation?.normalized_revision_id == null;
  }

  function renderHistory() {
    const rows = revisions[selectedKind] ?? [];
    element("configRevisionList").innerHTML = rows.length ? rows.map((revision) => {
      const rollback = isRollbackTarget(revision) && summary?.writes_enabled
        ? `<button class="text-button" type="button" data-config-rollback="${Number(revision.id)}">Rollback</button>`
        : "";
      return `<article class="config-history-row"><div><strong>${escapeHtml(revision.state)} · #${Number(revision.id)}</strong><small>${escapeHtml(revision.created_by)} · ${escapeHtml(revision.created_at)}</small></div>${rollback}</article>`;
    }).join("") : '<p class="detail-empty">No revisions available.</p>';
    element("configAuditList").innerHTML = auditEntries.length ? auditEntries.map((entry) =>
      `<article class="config-history-row"><div><strong>${escapeHtml(entry.action)}</strong><small>${escapeHtml(entry.actor)} · ${escapeHtml(entry.occurred_at)}</small></div></article>`
    ).join("") : '<p class="detail-empty">No configuration audit records.</p>';
    element("configRollbackGuard").classList.toggle("hidden", pendingRollbackId == null);
    element("configRollbackTitle").textContent = pendingRollbackId == null
      ? "Confirm rollback"
      : `Confirm rollback to revision #${pendingRollbackId}`;
    const target = rollbackTarget && rollbackTarget.id === pendingRollbackId
      ? rollbackTarget
      : null;
    // Operator-controlled document text is written as text, never as markup.
    element("configRollbackDocument").textContent = target
      ? JSON.stringify(target.document, null, 2)
      : "";
    // A rollback carries no impact preview at all, so an inventory rollback
    // cannot show what it does to asset-scoped prefilter decisions. The backend
    // refuses one without that acknowledgement whenever such rules are active;
    // asking for it on every inventory rollback keeps the operator's answer
    // conservative and needs no extra endpoint to discover the policy shape.
    const needsAssetAcknowledgement = selectedKind === "asset_inventory";
    element("configRollbackAssetGuard").classList.toggle(
      "hidden",
      !needsAssetAcknowledgement || pendingRollbackId == null,
    );
    // Nothing may be confirmed until the exact target document is on screen and
    // every acknowledgement this target actually needs is checked.
    element("configConfirmRollback").disabled = target == null
      || !rollbackAcknowledgementsSatisfied(target);
  }

  function rollbackTargetHasBroadRules(target) {
    const rules = target?.document?.auto_false_positive;
    return Array.isArray(rules) && rules.some((rule) => rule?.match == null);
  }

  function rollbackAcknowledgementsSatisfied(target) {
    if (target == null) return false;
    if (
      selectedKind === "asset_inventory"
      && !element("configConfirmRollbackAssetPreview").checked
    ) return false;
    // Unscoped rules are visible in the exact document already on screen, so
    // the same acknowledgement activation requires is required here too.
    if (
      rollbackTargetHasBroadRules(target)
      && !element("configRollbackAcknowledgeBroad").checked
    ) return false;
    return true;
  }

  function clearRollbackSelection() {
    pendingRollbackId = null;
    rollbackTarget = null;
    // Rollback acknowledgements are this selection's own state and never carry
    // over to another target, another kind, or the activation guard.
    element("configRollbackAcknowledgeBroad").checked = false;
    element("configRollbackAcknowledgeBase").checked = false;
    element("configConfirmRollbackAssetPreview").checked = false;
  }

  function renderEditor() {
    const prefilter = selectedKind === "prefilter_policy";
    element("configPrefilterPane").classList.toggle("hidden", !prefilter);
    element("configAssetPane").classList.toggle("hidden", prefilter);
    element("configPrefilterTab").classList.toggle("active", prefilter);
    element("configAssetTab").classList.toggle("active", !prefilter);
    renderPrefilter();
    renderAssets();
    renderExactDocument();
    renderLifecycle();
    renderHistory();
  }

  function invalidateLifecycle(message = "Candidate changed. Create a new immutable draft.") {
    lifecycle = emptyLifecycle();
    clearRollbackSelection();
    element("configConfirmActivate").checked = false;
    element("configAcknowledgeBroad").checked = false;
    element("configAcknowledgeBase").checked = false;
    element("configConfirmAssetPreview").checked = false;
    setMessage(message);
  }

  function markDirty() {
    // A local edit is newer than any load still in flight.
    invalidateInFlightResponses();
    dirtyKinds.add(selectedKind);
    invalidateLifecycle();
    renderEditor();
  }

  function selectKind(kind) {
    if (!KINDS.includes(kind)) return;
    if (selectedKind !== kind) {
      invalidateInFlightResponses();
      selectedKind = kind;
      lifecycle = emptyLifecycle();
      clearRollbackSelection();
      setMessage("");
    }
    renderEditor();
  }

  function editRule(index) {
    const rule = workingDocuments.prefilter_policy?.auto_false_positive?.[index];
    if (!rule) return;
    const match = rule.match ?? {};
    // The rule being edited is retained whole. The form represents only part of
    // a match, so applying it must narrow nothing the operator did not touch.
    noteFormActivity(FORM_SCOPES.rule);
    editingRule = clone(rule);
    element("configRuleIndex").value = String(index);
    element("configRuleSignatures").value = (rule.signature_ids ?? []).join(", ");
    element("configRuleReason").value = rule.reason ?? "";
    element("configRuleProtocol").value = match.protocols?.[0] ?? "";
    element("configRuleNetworkDirection").value = match.network_directions?.[0] ?? "";
    element("configRuleFlowDirection").value = match.flow_directions?.[0] ?? "";
    element("configRuleSourcePorts").value = (match.source_ports ?? []).join(", ");
    element("configRuleDestinationPorts").value = (match.destination_ports ?? []).join(", ");
    element("configRuleSourceCidrs").value = (match.source_cidrs ?? []).join(", ");
    element("configRuleDestinationCidrs").value = (match.destination_cidrs ?? []).join(", ");
    editingRuleForm = RULE_SELECT_FIELDS.reduce((snapshot, [, id]) => {
      snapshot[id] = element(id).value;
      return snapshot;
    }, {});
    element("configRuleFormTitle").textContent = `Edit rule ${index + 1}`;
    element("configRuleCancel").classList.remove("hidden");
    element("configRulePreserved").textContent = describePreservedConstraints(rule);
    element("configRuleReason").focus();
  }

  function ruleFromForm() {
    const signatures = csvIntegers(element("configRuleSignatures").value, "Signature IDs");
    if (!signatures.length) throw new Error("At least one signature ID is required.");
    const reason = element("configRuleReason").value.trim();
    if (!reason) throw new Error("A review reason is required.");
    // Start from the retained rule so selectors the form cannot express, such
    // as source_asset and destination_asset, survive any edit untouched.
    const rule = editingRule ? clone(editingRule) : {};
    const match = rule.match ? clone(rule.match) : {};
    RULE_SELECT_FIELDS.forEach(([key, id]) => {
      const value = element(id).value;
      // A single-value control shows only the first entry of a list. Leaving it
      // alone must keep every entry; changing it is an explicit narrowing, and
      // clearing it is an explicit removal.
      if (editingRuleForm && editingRuleForm[id] === value) return;
      if (value) match[key] = [value];
      else delete match[key];
    });
    RULE_NUMBER_LIST_FIELDS.forEach(([key, id, label]) => {
      const values = csvIntegers(element(id).value, label);
      if (values.length) match[key] = values;
      else delete match[key];
    });
    RULE_TEXT_LIST_FIELDS.forEach(([key, id]) => {
      const values = csvStrings(element(id).value);
      if (values.length) match[key] = values;
      else delete match[key];
    });
    rule.signature_ids = signatures;
    rule.reason = reason;
    if (Object.keys(match).length) rule.match = match;
    else delete rule.match;
    return rule;
  }

  function applyRule(event) {
    event.preventDefault();
    try {
      const policy = workingDocuments.prefilter_policy;
      policy.internal_cidrs = csvStrings(element("configInternalCidrs").value);
      const rawIndex = element("configRuleIndex").value;
      const index = rawIndex === "" ? -1 : Number(rawIndex);
      const rule = ruleFromForm();
      if (Number.isInteger(index) && index >= 0) policy.auto_false_positive[index] = rule;
      else policy.auto_false_positive.push(rule);
      selectedKind = "prefilter_policy";
      resetRuleForm();
      markDirty();
    } catch (error) {
      setMessage(error.message, true);
    }
  }

  function editAsset(index) {
    const asset = workingDocuments.asset_inventory?.assets?.[index];
    if (!asset) return;
    noteFormActivity(FORM_SCOPES.asset);
    element("configAssetIndex").value = String(index);
    element("configAssetHostname").value = asset.hostname ?? "";
    element("configAssetRole").value = asset.role ?? "";
    element("configAssetIps").value = (asset.ips ?? []).join(", ");
    element("configAssetCriticality").value = asset.criticality ?? "low";
    element("configAssetInternetFacing").checked = Boolean(asset.internet_facing);
    element("configAssetPorts").value = (asset.exposed_ports ?? []).map((port) => `${port.protocol}/${port.port}`).join(", ");
    element("configAssetFormTitle").textContent = `Edit ${asset.hostname}`;
    element("configAssetCancel").classList.remove("hidden");
    element("configAssetHostname").focus();
  }

  function assetFromForm() {
    const ports = csvStrings(element("configAssetPorts").value).map((value) => {
      const match = /^(tcp|udp)\/(\d+)$/.exec(value.toLowerCase());
      if (!match) throw new Error("Exposed ports must use protocol/port, for example tcp/443.");
      return { protocol: match[1], port: Number(match[2]) };
    });
    return {
      hostname: element("configAssetHostname").value.trim(),
      role: element("configAssetRole").value.trim(),
      ips: csvStrings(element("configAssetIps").value),
      criticality: element("configAssetCriticality").value,
      internet_facing: element("configAssetInternetFacing").checked,
      exposed_ports: ports,
    };
  }

  function applyAsset(event) {
    event.preventDefault();
    try {
      const inventory = workingDocuments.asset_inventory;
      const rawIndex = element("configAssetIndex").value;
      const index = rawIndex === "" ? -1 : Number(rawIndex);
      const asset = assetFromForm();
      if (!asset.hostname || !asset.role || !asset.ips.length) {
        throw new Error("Hostname, role, and at least one IP address are required.");
      }
      if (Number.isInteger(index) && index >= 0) inventory.assets[index] = asset;
      else inventory.assets.push(asset);
      selectedKind = "asset_inventory";
      resetAssetForm();
      markDirty();
    } catch (error) {
      setMessage(error.message, true);
    }
  }

  async function createDraft() {
    try {
      const payload = await configRequest(`/api/v1/config/${selectedKind}/drafts`, {
        method: "POST",
        body: JSON.stringify({
          document: workingDocuments[selectedKind],
          parent_revision_id: summary.active[selectedKind].id,
          expected_generation: summary.generation,
          note: element("configChangeNote").value.trim() || null,
        }),
      });
      // An identical candidate may already exist when editor state was lost.
      // The server returns it only when it is still resumable against the
      // current active parent and generation, so the lifecycle continues from
      // that immutable revision instead of demanding a changed document. A
      // resumed handle that already validated -- in place or by normalizing
      // onto canonical content -- resumes directly at preview.
      const validatedRevisionId = payload.resumed
        ? payload.validated_revision_id ?? null
        : null;
      // The note has now been applied to an immutable draft, so it is no
      // longer unapplied work.
      clearFormScope(FORM_SCOPES.note);
      lifecycle = {
        kind: selectedKind,
        draftId: payload.draft.id,
        validatedId: validatedRevisionId,
        preview: null,
      };
      setMessage(payload.resumed
        ? `Resumed ${payload.draft.state} revision #${payload.draft.id}. ${validatedRevisionId ? "Review its bounded impact next." : "Validate it next."}`
        : `Immutable draft #${payload.draft.id} created. Validate it next.`);
      renderLifecycle();
    } catch (error) {
      setMessage(error.status === 409 ? `${error.message} Reload active configuration before retrying.` : error.message, true);
    }
  }

  async function validateDraft() {
    // Validation spans two requests and ends by replacing the working document,
    // so it needs the same ownership proof a preview does. Without it, a
    // response that lands after the operator edited, switched kinds, reloaded,
    // or started a newer draft would overwrite that newer work with the old
    // draft's canonical content -- and could fetch it through the wrong kind.
    const identity = lifecycleIdentity();
    try {
      const payload = await configRequest(
        `/api/v1/config/${identity.selectedKind}/drafts/${identity.draftId}/validate`,
        { method: "POST" },
      );
      if (!ownsCurrentLifecycle(identity)) return;
      // Validation status is the verdict. Canonical content can normalize onto
      // an existing immutable revision whose own state is historical; that is a
      // valid candidate, and the submitted draft still carries its lineage.
      if (payload.validation?.status !== "valid") {
        lifecycle = emptyLifecycle();
        setMessage(`Validation rejected the candidate: ${JSON.stringify(payload.validation)}`, true);
        renderLifecycle();
        return;
      }
      // The canonical document is read through the kind this validation was
      // started for, never through whichever kind is selected when it returns.
      const canonical = await configRequest(
        `/api/v1/config/${identity.selectedKind}/revisions/${payload.revision.id}`,
      );
      // Ownership is re-proved after the second await, and only then are the
      // validated id and the canonical document published together.
      if (!ownsCurrentLifecycle(identity)) return;
      lifecycle.validatedId = payload.revision.id;
      workingDocuments[identity.selectedKind] = canonical.document;
      setMessage(`Validated revision #${payload.revision.id}. Review its bounded impact next.`);
      renderEditor();
    } catch (error) {
      // A failure belongs to the lifecycle that asked for it, so a superseded
      // one reports nothing over newer work.
      if (!ownsCurrentLifecycle(identity)) return;
      setMessage(error.message, true);
    }
  }

  function lifecycleIdentity() {
    // Everything that decides which change an impact analysis describes. A
    // response may only be published while all of it still holds.
    return {
      epoch: stateEpoch,
      kind: lifecycle.kind,
      selectedKind,
      draftId: lifecycle.draftId,
      validatedId: lifecycle.validatedId,
      generation: summary?.generation ?? null,
      parentRevisionId: summary?.active?.[selectedKind]?.id ?? null,
    };
  }

  function ownsCurrentLifecycle(identity) {
    const current = lifecycleIdentity();
    return Object.keys(identity).every((key) => identity[key] === current[key]);
  }

  async function previewDraft() {
    // An impact analysis is only meaningful for the exact draft, revision,
    // generation, and parent it was requested for. A slow response must never
    // be attached to whatever the editor happens to be holding when it lands:
    // that is what would let one draft be activated while another draft's
    // impact is on screen.
    const identity = lifecycleIdentity();
    try {
      const payload = await configRequest(`/api/v1/config/${identity.selectedKind}/drafts/${identity.draftId}/preview`, {
        method: "POST",
        body: JSON.stringify({ expected_generation: identity.generation }),
      });
      if (!ownsCurrentLifecycle(identity)) return;
      lifecycle.preview = payload;
      const host = element("configPreviewResult");
      host.classList.remove("hidden");
      host.textContent = JSON.stringify({
        window_hours: payload.window_hours,
        candidates_examined: payload.candidates_examined,
        truncated: payload.truncated,
        warnings: payload.warnings,
        summary: payload.summary,
      }, null, 2);
      setMessage("Preview complete. Activation affects only future records.");
      renderLifecycle();
    } catch (error) {
      // A failure belongs to the lifecycle that asked for it, so a superseded
      // one reports nothing over newer work.
      if (!ownsCurrentLifecycle(identity)) return;
      setMessage(error.status === 409 ? `${error.message} Reload active configuration before retrying.` : error.message, true);
    }
  }

  async function activateDraft() {
    if (!element("configConfirmActivate").checked || !lifecycle.preview) return;
    // The disabled control is the visible guard; this is the real one. An
    // incomplete asset analysis is never activated on the general confirmation
    // alone, whatever state the button is in.
    if (
      lifecycle.preview.summary?.suppression?.complete === false
      && !element("configConfirmAssetPreview").checked
    ) {
      setMessage(
        "This preview could not evaluate every asset-scoped prefilter rule. Acknowledge that before activating.",
        true,
      );
      return;
    }
    try {
      const payload = await configRequest(`/api/v1/config/${selectedKind}/drafts/${lifecycle.draftId}/activate`, {
        method: "POST",
        body: JSON.stringify({
          expected_generation: summary.generation,
          acknowledge_broad_rules: element("configAcknowledgeBroad").checked,
          acknowledge_shipped_base_change: element("configAcknowledgeBase").checked,
          acknowledge_incomplete_asset_preview: element("configConfirmAssetPreview").checked,
        }),
      });
      await load(true);
      setMessage(`Generation ${payload.generation} activated. Runtime consumers will reload between records.`);
    } catch (error) {
      setMessage(error.status === 409 ? `${error.message} Review the acknowledgement controls or reload active configuration.` : error.message, true);
    }
  }

  async function rollbackRevision(revisionId) {
    // The disabled control is the visible guard; this is the real one. Rollback
    // is never sent for a revision whose exact document was not displayed.
    if (rollbackTarget?.id !== revisionId) {
      setMessage(`Load revision #${revisionId} before confirming rollback.`, true);
      return;
    }
    // The disabled control is the visible guard; this is the real one. A forced
    // click without the acknowledgements this target needs sends nothing.
    if (!rollbackAcknowledgementsSatisfied(rollbackTarget)) {
      setMessage(
        `Acknowledge the rollback conditions for revision #${revisionId} before confirming.`,
        true,
      );
      return;
    }
    try {
      const payload = await configRequest(`/api/v1/config/${selectedKind}/revisions/${revisionId}/rollback`, {
        method: "POST",
        body: JSON.stringify({
          expected_generation: summary.generation,
          acknowledge_broad_rules: element("configRollbackAcknowledgeBroad").checked,
          acknowledge_shipped_base_change: element("configRollbackAcknowledgeBase").checked,
          acknowledge_incomplete_asset_preview: element("configConfirmRollbackAssetPreview").checked,
        }),
      });
      await load(true);
      setMessage(`Rolled back to revision #${revisionId} as generation ${payload.generation}.`);
    } catch (error) {
      setMessage(error.status === 409 ? `${error.message} Review the rollback acknowledgements or reload active configuration.` : error.message, true);
    }
  }

  async function selectRollbackRevision(revisionId) {
    const epoch = stateEpoch;
    // Clear first, then claim this selection: a previous target's
    // acknowledgements never carry over to a new one.
    clearRollbackSelection();
    pendingRollbackId = revisionId;
    renderHistory();
    setMessage(`Loading revision #${revisionId} for review…`);
    try {
      const payload = await configRequest(
        `/api/v1/config/${selectedKind}/revisions/${revisionId}`,
      );
      if (epoch !== stateEpoch || pendingRollbackId !== revisionId) return;
      rollbackTarget = { id: revisionId, document: payload.document };
      renderHistory();
      setMessage(`Review the exact revision #${revisionId} below, then confirm rollback.`);
    } catch (error) {
      if (epoch !== stateEpoch || pendingRollbackId !== revisionId) return;
      // Never leave confirmation available against an unseen document.
      rollbackTarget = null;
      renderHistory();
      setMessage(`Revision #${revisionId} could not be loaded: ${error.message}`, true);
    }
  }

  function cancelRollback() {
    clearRollbackSelection();
    renderHistory();
  }

  function applyPendingSeed({ fromLoad = false } = {}) {
    // While another load is in flight the cache is about to be replaced, so the
    // seed waits: that load applies it against the snapshot it publishes.
    if (!pendingSeed || !loaded || (loading && !fromLoad)) return;
    const seed = pendingSeed;
    pendingSeed = null;
    if (seed.action === "prefilter") {
      selectKind("prefilter_policy");
      resetRuleForm();
      element("configRuleSignatures").value = seed.signatureId == null ? "" : String(seed.signatureId);
      element("configRuleReason").value = seed.signature ? `Reviewed false positive: ${seed.signature}` : "Reviewed false positive";
      element("configRuleProtocol").value = ["tcp", "udp", "icmp", "icmpv6"].includes(seed.protocol) ? seed.protocol : "";
      element("configRuleFlowDirection").value = ["to_server", "to_client"].includes(seed.flowDirection) ? seed.flowDirection : "";
      element("configRuleSourcePorts").value = seed.sourcePort ?? "";
      element("configRuleDestinationPorts").value = seed.destinationPort ?? "";
      // Evidence the operator has not applied yet is unapplied work, whether
      // they typed it or an alert handoff filled it in for them.
      noteFormActivity(FORM_SCOPES.rule);
      setMessage("Alert evidence populated the rule form. Review its scope before applying it to the candidate.");
      element("configRuleReason").focus();
    } else {
      selectKind("asset_inventory");
      resetAssetForm();
      // The retained alert address decides the mode. An address already owned
      // by an asset in the freshly loaded inventory is edited in place, with
      // every current field and every other address preserved; only an unknown
      // address opens Add.
      // This says which inventory answered the ownership question. It must not
      // claim anything was preserved: the form it is about to fill may have
      // just been replaced with the operator's explicit consent.
      const staleWarning = seed.resolvedAgainstCandidate
        ? " This used your local inventory candidate, which may be older than the active configuration."
        : "";
      const existingIndex = assetIndexForAddress(seed.ip);
      if (existingIndex >= 0) {
        editAsset(existingIndex);
        setMessage(
          `Editing the existing asset that already owns ${seed.ip}. Its other addresses are preserved.${staleWarning}`,
          Boolean(staleWarning),
        );
        return;
      }
      element("configAssetHostname").value = seed.asset?.hostname ?? "new-asset";
      element("configAssetRole").value = seed.asset?.role ?? "endpoint";
      element("configAssetIps").value = seed.ip ?? "";
      element("configAssetCriticality").value = seed.asset?.criticality ?? "medium";
      element("configAssetInternetFacing").checked = Boolean(seed.asset?.internet_facing);
      element("configAssetPorts").value = (seed.asset?.exposed_ports ?? []).map((port) => `${port.protocol}/${port.port}`).join(", ");
      noteFormActivity(FORM_SCOPES.asset);
      setMessage(
        `Alert evidence populated the asset form. Review it before applying it to the candidate.${staleWarning}`,
        Boolean(staleWarning),
      );
      element("configAssetHostname").focus();
    }
  }

  function normalizedAddress(value) {
    return String(value ?? "").trim().toLowerCase();
  }

  function assetIndexForAddress(address) {
    const wanted = normalizedAddress(address);
    if (!wanted) return -1;
    const assets = workingDocuments.asset_inventory?.assets;
    if (!Array.isArray(assets)) return -1;
    return assets.findIndex((asset) =>
      (asset?.ips ?? []).some((ip) => normalizedAddress(ip) === wanted)
    );
  }

  async function seedFromAlert(verdict, action) {
    const side = action === "asset-source" ? "source" : "destination";
    pendingSeed = action === "prefilter" ? {
      action,
      signatureId: verdict?.signature_id,
      signature: verdict?.signature,
      protocol: String(verdict?.proto ?? "").toLowerCase(),
      flowDirection: verdict?.direction,
      sourcePort: verdict?.src_port,
      destinationPort: verdict?.dest_port,
    } : {
      action,
      ip: side === "source" ? verdict?.src_ip : verdict?.dest_ip,
      asset: clone(verdict?.asset_context?.[side] ?? null),
    };
    // A handoff fills the form it targets, so it replaces whatever unapplied
    // input is already there. Only that form's own scope is asked about: a
    // half-written change note, typed CIDRs, or work in the other editor are
    // not this handoff's to discard, and must not raise a prompt either.
    const targetScope = action === "prefilter" ? FORM_SCOPES.rule : FORM_SCOPES.asset;
    if (loaded && dirtyForms.has(targetScope)) {
      const label = action === "prefilter" ? "rule" : "asset";
      const replace = global.confirm(
        `Replace your unapplied ${label} form input with this alert's evidence?`,
      );
      if (!replace) {
        // Declined: the form and its dirty marker stay exactly as they are, and
        // the handoff is dropped rather than left queued to fire later. Keeping
        // this input is itself a decision newer than any reload in flight, which
        // may therefore no longer reset the form the operator just kept.
        invalidateInFlightResponses();
        pendingSeed = null;
        setMessage(
          `Kept your unapplied ${label} form input. The alert evidence was not applied.`,
        );
        return undefined;
      }
      // The operator authorized replacing this form's contents.
      clearFormScope(targetScope);
    }
    // Whether this address is already owned decides Add versus Edit, so that
    // question has to be asked of a current, coherent inventory. A cached one
    // can be older than the active generation and would open Add for an
    // address the active inventory already owns.
    const decidesOwnership = action !== "prefilter";
    const hasLocalWork = dirtyKinds.size > 0 || hasUnappliedFormWork();
    if (decidesOwnership && loaded && !hasLocalWork) {
      // Nothing local to lose: refresh, then decide. The load applies the seed.
      return load(true);
    }
    if (decidesOwnership && hasLocalWork) {
      // Other unsaved work is never discarded to answer this question, so the
      // decision is made against the working candidate and the operator is told
      // which inventory it used.
      pendingSeed.resolvedAgainstCandidate = true;
    }
    return applyPendingSeed();
  }

  async function load(force = false) {
    initialize();
    if (!apiKey) {
      renderConnection(false);
      return;
    }
    if (!force && (loading || loaded)) {
      applyPendingSeed();
      return;
    }
    // A forced load always starts, even while an older one is in flight: a new
    // credential submission must never be dropped because the previous key is
    // still loading. Ownership of `loading` and of the header status moves to
    // the newest load, so the older one's completion cannot clear or overwrite
    // what the newer one is doing.
    const epoch = invalidateInFlightResponses();
    const credential = apiKey;
    loading = true;
    loadingEpoch = epoch;
    let published = false;
    setConnectionStatus("Loading configuration…");
    try {
      const snapshot = await readConsistentSnapshot(epoch, credential);
      if (snapshot === null) return;
      published = true;
      summary = snapshot.summary;
      activeDocuments = {
        prefilter_policy: snapshot.prefilter.document,
        asset_inventory: snapshot.assets.document,
      };
      workingDocuments = clone(activeDocuments);
      revisions = {
        prefilter_policy: snapshot.prefilterHistory.revisions,
        asset_inventory: snapshot.assetHistory.revisions,
      };
      auditEntries = snapshot.audit.entries;
      dirtyKinds = new Set();
      // This load was never superseded, so every surface it is about to reset
      // genuinely had no newer operator work in it.
      dirtyForms = new Set();
      lifecycle = emptyLifecycle();
      clearRollbackSelection();
      loaded = true;
      element("configCredentialHelp").textContent = CREDENTIAL_HELP;
      renderConnection(true);
      renderSummary();
      resetRuleForm();
      resetAssetForm();
      renderEditor();
      setMessage("");
      applyPendingSeed({ fromLoad: true });
    } catch (error) {
      // A superseded load reports nothing: its failure belongs to a credential
      // or a snapshot the operator has already replaced.
      if (epoch !== stateEpoch) return;
      published = true;
      loaded = false;
      renderConnection(false);
      setConnectionStatus([401, 403].includes(error.status) ? "Key rejected" : "Configuration unavailable", "error");
      element("configCredentialPanel").classList.remove("hidden");
      element("configCredentialHelp").textContent = error.message;
    } finally {
      if (loadingEpoch === epoch) {
        loading = false;
        loadingEpoch = null;
        // This load owned the "Loading…" status and published nothing, so it
        // must hand the header back to the state that is actually current
        // rather than leaving it stuck.
        if (!published) renderConnection(Boolean(apiKey) && loaded);
      }
    }
  }

  function snapshotIsConsistent(summaryPayload, prefilter, assets) {
    // Each document is fetched independently, so a generation that advances
    // mid-load can pair one document's bytes with the other's parent. Editing
    // that mixture would submit stale content against a newer parent, so the
    // whole snapshot is discarded rather than published.
    const pairs = [
      [prefilter, summaryPayload?.active?.prefilter_policy],
      [assets, summaryPayload?.active?.asset_inventory],
    ];
    return pairs.every(([document, active]) =>
      document?.generation === summaryPayload?.generation
      && active != null
      && document?.revision?.id === active.id
    );
  }

  async function readConsistentSnapshot(epoch, credential, attempt = 0) {
    const [summaryPayload, prefilter, assets, prefilterHistory, assetHistory, audit] = await Promise.all([
      configRequest("/api/v1/config", {}, credential),
      configRequest("/api/v1/config/prefilter_policy", {}, credential),
      configRequest("/api/v1/config/asset_inventory", {}, credential),
      configRequest("/api/v1/config/prefilter_policy/revisions?limit=25", {}, credential),
      configRequest("/api/v1/config/asset_inventory/revisions?limit=25", {}, credential),
      configRequest("/api/v1/config/audit?limit=25", {}, credential),
    ]);
    if (epoch !== stateEpoch) return null;
    if (!snapshotIsConsistent(summaryPayload, prefilter, assets)) {
      if (attempt >= MAX_SNAPSHOT_ATTEMPTS - 1) {
        throw new Error(
          "Active configuration changed while loading. Reload active configuration to continue.",
        );
      }
      return readConsistentSnapshot(epoch, credential, attempt + 1);
    }
    return {
      summary: summaryPayload,
      prefilter,
      assets,
      prefilterHistory,
      assetHistory,
      audit,
    };
  }

  function forget() {
    // Disconnecting is newer than any load still in flight, so no response may
    // publish configuration state after the credential is dropped.
    invalidateInFlightResponses();
    apiKey = "";
    summary = null;
    activeDocuments = {};
    workingDocuments = {};
    revisions = {};
    auditEntries = [];
    dirtyKinds = new Set();
    dirtyForms = new Set();
    lifecycle = emptyLifecycle();
    clearRollbackSelection();
    loaded = false;
    // No load owns the header any more; the disconnected state does.
    loading = false;
    loadingEpoch = null;
    element("configApiKey").value = "";
    element("configCredentialHelp").textContent = CREDENTIAL_HELP;
    renderConnection(false);
  }

  function handleWorkspaceClick(event) {
    const target = event.target;
    const kindButton = target.closest?.("[data-config-kind]");
    if (kindButton) return selectKind(kindButton.dataset.configKind);
    const ruleEdit = target.closest?.("[data-config-rule-edit]");
    if (ruleEdit) return editRule(Number(ruleEdit.dataset.configRuleEdit));
    const ruleRemove = target.closest?.("[data-config-rule-remove]");
    if (ruleRemove) {
      workingDocuments.prefilter_policy.auto_false_positive.splice(Number(ruleRemove.dataset.configRuleRemove), 1);
      selectedKind = "prefilter_policy";
      return markDirty();
    }
    const assetEdit = target.closest?.("[data-config-asset-edit]");
    if (assetEdit) return editAsset(Number(assetEdit.dataset.configAssetEdit));
    const assetRemove = target.closest?.("[data-config-asset-remove]");
    if (assetRemove) {
      workingDocuments.asset_inventory.assets.splice(Number(assetRemove.dataset.configAssetRemove), 1);
      selectedKind = "asset_inventory";
      return markDirty();
    }
    const rollback = target.closest?.("[data-config-rollback]");
    if (rollback) return selectRollbackRevision(Number(rollback.dataset.configRollback));
    return undefined;
  }

  function initialize() {
    if (initialized) return;
    initialized = true;
    element("configCredentialForm").addEventListener("submit", (event) => {
      event.preventDefault();
      const submitted = element("configApiKey").value.trim();
      // The field is cleared immediately and the key lives only in this
      // closure's memory for the life of the session it starts.
      element("configApiKey").value = "";
      if (!submitted) return undefined;
      // Every submission starts its own session: nothing already in flight may
      // publish under it, and this key always gets its own attempt even when an
      // earlier load has not finished.
      apiKey = submitted;
      loaded = false;
      return load(true);
    });
    element("configWorkspace").addEventListener("click", handleWorkspaceClick);
    element("configPrefilterForm").addEventListener("submit", applyRule);
    element("configAssetForm").addEventListener("submit", applyAsset);
    // Typing a CIDR is protected from the keystroke, before the change event
    // commits it into the candidate document.
    element("configInternalCidrs").addEventListener("input", () => {
      noteFormActivity(FORM_SCOPES.cidrs);
    });
    element("configInternalCidrs").addEventListener("change", () => {
      workingDocuments.prefilter_policy.internal_cidrs = csvStrings(element("configInternalCidrs").value);
      selectedKind = "prefilter_policy";
      clearFormScope(FORM_SCOPES.cidrs);
      markDirty();
    });
    element("configRuleCancel").addEventListener("click", cancelRuleForm);
    element("configAssetCancel").addEventListener("click", cancelAssetForm);
    element("configForgetButton").addEventListener("click", forget);
    element("configReloadButton").addEventListener("click", () => {
      // An explicitly confirmed reload is allowed to discard both an edited
      // candidate and every surface's unapplied input; nothing else is.
      if (
        (dirtyKinds.size || hasUnappliedFormWork())
        && !global.confirm("Discard unsaved candidate changes and reload active configuration?")
      ) return undefined;
      return load(true);
    });
    const scopedInputs = [
      [RULE_FORM_INPUT_IDS, FORM_SCOPES.rule],
      [ASSET_FORM_INPUT_IDS, FORM_SCOPES.asset],
      [NOTE_FORM_INPUT_IDS, FORM_SCOPES.note],
    ];
    scopedInputs.forEach(([ids, scope]) => {
      ids.forEach((id) => {
        const handler = () => noteFormActivity(scope);
        element(id).addEventListener("input", handler);
        element(id).addEventListener("change", handler);
      });
    });
    element("configCreateDraft").addEventListener("click", createDraft);
    element("configValidateDraft").addEventListener("click", validateDraft);
    element("configPreviewDraft").addEventListener("click", previewDraft);
    element("configActivateDraft").addEventListener("click", activateDraft);
    element("configConfirmActivate").addEventListener("change", renderLifecycle);
    element("configConfirmAssetPreview").addEventListener("change", renderLifecycle);
    element("configConfirmRollback").addEventListener("click", () => {
      if (pendingRollbackId != null) return rollbackRevision(pendingRollbackId);
    });
    element("configCancelRollback").addEventListener("click", cancelRollback);
    [
      "configRollbackAcknowledgeBroad",
      "configRollbackAcknowledgeBase",
      "configConfirmRollbackAssetPreview",
    ].forEach((id) => {
      element(id).addEventListener("change", renderHistory);
    });
  }

  global.TriagewallConfigEditor = {
    load,
    forget,
    seedFromAlert,
    state: () => ({
      connected: Boolean(apiKey),
      loaded,
      selectedKind,
      generation: summary?.generation ?? null,
      lifecycle: { ...lifecycle },
      dirtyKinds: [...dirtyKinds],
      dirtyForms: [...dirtyForms],
    }),
  };
})(window);
