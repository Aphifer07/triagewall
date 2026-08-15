(function installConfigurationEditor(global) {
  "use strict";

  const KINDS = ["prefilter_policy", "asset_inventory"];
  const CREDENTIAL_HELP = "The key must carry config:write. It is kept only in this page's memory and is cleared on reload or disconnect.";
  let apiKey = "";
  let initialized = false;
  let loaded = false;
  let loading = false;
  let summary = null;
  let selectedKind = "prefilter_policy";
  let activeDocuments = {};
  let workingDocuments = {};
  let revisions = {};
  let auditEntries = [];
  let dirtyKinds = new Set();
  let lifecycle = emptyLifecycle();
  let pendingRollbackId = null;
  let pendingSeed = null;

  function emptyLifecycle() {
    return { kind: null, draftId: null, validatedId: null, preview: null };
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

  async function configRequest(path, options = {}) {
    if (!apiKey) throw new Error("Enter a configuration API key first.");
    const headers = new Headers(options.headers || {});
    headers.set("X-API-Key", apiKey);
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

  function resetRuleForm() {
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
  }

  function resetAssetForm() {
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
    element("configInternalCidrs").value = (document.internal_cidrs ?? []).join(", ");
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
    element("configActivateDraft").disabled = !hasPreview || !element("configConfirmActivate").checked;
    if (!hasPreview) {
      element("configPreviewResult").classList.add("hidden");
      element("configPreviewResult").textContent = "";
    }
  }

  function renderHistory() {
    const rows = revisions[selectedKind] ?? [];
    element("configRevisionList").innerHTML = rows.length ? rows.map((revision) => {
      const rollback = revision.state === "superseded" && summary?.writes_enabled
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
    pendingRollbackId = null;
    element("configConfirmActivate").checked = false;
    element("configAcknowledgeBroad").checked = false;
    element("configAcknowledgeBase").checked = false;
    setMessage(message);
  }

  function markDirty() {
    dirtyKinds.add(selectedKind);
    invalidateLifecycle();
    renderEditor();
  }

  function selectKind(kind) {
    if (!KINDS.includes(kind)) return;
    if (selectedKind !== kind) {
      selectedKind = kind;
      lifecycle = emptyLifecycle();
      pendingRollbackId = null;
      setMessage("");
    }
    renderEditor();
  }

  function editRule(index) {
    const rule = workingDocuments.prefilter_policy?.auto_false_positive?.[index];
    if (!rule) return;
    const match = rule.match ?? {};
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
    element("configRuleFormTitle").textContent = `Edit rule ${index + 1}`;
    element("configRuleCancel").classList.remove("hidden");
    element("configRuleReason").focus();
  }

  function ruleFromForm() {
    const signatures = csvIntegers(element("configRuleSignatures").value, "Signature IDs");
    if (!signatures.length) throw new Error("At least one signature ID is required.");
    const reason = element("configRuleReason").value.trim();
    if (!reason) throw new Error("A review reason is required.");
    const match = {};
    const scalarLists = [
      ["protocols", "configRuleProtocol"],
      ["network_directions", "configRuleNetworkDirection"],
      ["flow_directions", "configRuleFlowDirection"],
    ];
    scalarLists.forEach(([key, id]) => {
      const value = element(id).value;
      if (value) match[key] = [value];
    });
    const numericLists = [
      ["source_ports", "configRuleSourcePorts", "Source ports"],
      ["destination_ports", "configRuleDestinationPorts", "Destination ports"],
    ];
    numericLists.forEach(([key, id, label]) => {
      const values = csvIntegers(element(id).value, label);
      if (values.length) match[key] = values;
    });
    const textLists = [
      ["source_cidrs", "configRuleSourceCidrs"],
      ["destination_cidrs", "configRuleDestinationCidrs"],
    ];
    textLists.forEach(([key, id]) => {
      const values = csvStrings(element(id).value);
      if (values.length) match[key] = values;
    });
    const rule = { signature_ids: signatures, reason };
    if (Object.keys(match).length) rule.match = match;
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
      lifecycle = { kind: selectedKind, draftId: payload.draft.id, validatedId: null, preview: null };
      setMessage(`Immutable draft #${payload.draft.id} created. Validate it next.`);
      renderLifecycle();
    } catch (error) {
      setMessage(error.status === 409 ? `${error.message} Reload active configuration before retrying.` : error.message, true);
    }
  }

  async function validateDraft() {
    try {
      const payload = await configRequest(`/api/v1/config/${selectedKind}/drafts/${lifecycle.draftId}/validate`, { method: "POST" });
      if (payload.revision.state !== "validated") {
        lifecycle = emptyLifecycle();
        setMessage(`Validation rejected the candidate: ${JSON.stringify(payload.validation)}`, true);
        renderLifecycle();
        return;
      }
      lifecycle.validatedId = payload.revision.id;
      const canonical = await configRequest(`/api/v1/config/${selectedKind}/revisions/${payload.revision.id}`);
      workingDocuments[selectedKind] = canonical.document;
      setMessage(`Validated revision #${payload.revision.id}. Review its bounded impact next.`);
      renderEditor();
    } catch (error) {
      setMessage(error.message, true);
    }
  }

  async function previewDraft() {
    try {
      const payload = await configRequest(`/api/v1/config/${selectedKind}/drafts/${lifecycle.validatedId}/preview`, {
        method: "POST",
        body: JSON.stringify({ expected_generation: summary.generation }),
      });
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
      setMessage(error.status === 409 ? `${error.message} Reload active configuration before retrying.` : error.message, true);
    }
  }

  async function activateDraft() {
    if (!element("configConfirmActivate").checked || !lifecycle.preview) return;
    try {
      const payload = await configRequest(`/api/v1/config/${selectedKind}/drafts/${lifecycle.validatedId}/activate`, {
        method: "POST",
        body: JSON.stringify({
          expected_generation: summary.generation,
          acknowledge_broad_rules: element("configAcknowledgeBroad").checked,
          acknowledge_shipped_base_change: element("configAcknowledgeBase").checked,
        }),
      });
      await load(true);
      setMessage(`Generation ${payload.generation} activated. Runtime consumers will reload between records.`);
    } catch (error) {
      setMessage(error.status === 409 ? `${error.message} Review the acknowledgement controls or reload active configuration.` : error.message, true);
    }
  }

  async function rollbackRevision(revisionId) {
    try {
      const payload = await configRequest(`/api/v1/config/${selectedKind}/revisions/${revisionId}/rollback`, {
        method: "POST",
        body: JSON.stringify({
          expected_generation: summary.generation,
          acknowledge_broad_rules: element("configRollbackAcknowledgeBroad").checked,
          acknowledge_shipped_base_change: element("configRollbackAcknowledgeBase").checked,
        }),
      });
      await load(true);
      setMessage(`Rolled back to revision #${revisionId} as generation ${payload.generation}.`);
    } catch (error) {
      setMessage(error.status === 409 ? `${error.message} Review the rollback acknowledgements or reload active configuration.` : error.message, true);
    }
  }

  function selectRollbackRevision(revisionId) {
    pendingRollbackId = revisionId;
    element("configRollbackAcknowledgeBroad").checked = false;
    element("configRollbackAcknowledgeBase").checked = false;
    renderHistory();
    setMessage(`Review revision #${revisionId} and confirm rollback below.`);
  }

  function cancelRollback() {
    pendingRollbackId = null;
    renderHistory();
  }

  function applyPendingSeed() {
    if (!pendingSeed || !loaded) return;
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
      setMessage("Alert evidence populated the rule form. Review its scope before applying it to the candidate.");
      element("configRuleReason").focus();
    } else {
      selectKind("asset_inventory");
      resetAssetForm();
      element("configAssetHostname").value = seed.asset?.hostname ?? "new-asset";
      element("configAssetRole").value = seed.asset?.role ?? "endpoint";
      element("configAssetIps").value = seed.ip ?? "";
      element("configAssetCriticality").value = seed.asset?.criticality ?? "medium";
      element("configAssetInternetFacing").checked = Boolean(seed.asset?.internet_facing);
      element("configAssetPorts").value = (seed.asset?.exposed_ports ?? []).map((port) => `${port.protocol}/${port.port}`).join(", ");
      setMessage("Alert evidence populated the asset form. Review it before applying it to the candidate.");
      element("configAssetHostname").focus();
    }
  }

  function seedFromAlert(verdict, action) {
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
    applyPendingSeed();
  }

  async function load(force = false) {
    initialize();
    if (!apiKey) {
      renderConnection(false);
      return;
    }
    if (loading || (loaded && !force)) {
      applyPendingSeed();
      return;
    }
    loading = true;
    setConnectionStatus("Loading configuration…");
    try {
      const [nextSummary, prefilter, assets, prefilterHistory, assetHistory, audit] = await Promise.all([
        configRequest("/api/v1/config"),
        configRequest("/api/v1/config/prefilter_policy"),
        configRequest("/api/v1/config/asset_inventory"),
        configRequest("/api/v1/config/prefilter_policy/revisions?limit=25"),
        configRequest("/api/v1/config/asset_inventory/revisions?limit=25"),
        configRequest("/api/v1/config/audit?limit=25"),
      ]);
      summary = nextSummary;
      activeDocuments = {
        prefilter_policy: prefilter.document,
        asset_inventory: assets.document,
      };
      workingDocuments = clone(activeDocuments);
      revisions = {
        prefilter_policy: prefilterHistory.revisions,
        asset_inventory: assetHistory.revisions,
      };
      auditEntries = audit.entries;
      dirtyKinds = new Set();
      lifecycle = emptyLifecycle();
      pendingRollbackId = null;
      loaded = true;
      element("configCredentialHelp").textContent = CREDENTIAL_HELP;
      renderConnection(true);
      renderSummary();
      resetRuleForm();
      resetAssetForm();
      renderEditor();
      setMessage("");
      applyPendingSeed();
    } catch (error) {
      loaded = false;
      renderConnection(false);
      setConnectionStatus([401, 403].includes(error.status) ? "Key rejected" : "Configuration unavailable", "error");
      element("configCredentialPanel").classList.remove("hidden");
      element("configCredentialHelp").textContent = error.message;
    } finally {
      loading = false;
    }
  }

  function forget() {
    apiKey = "";
    summary = null;
    activeDocuments = {};
    workingDocuments = {};
    revisions = {};
    auditEntries = [];
    dirtyKinds = new Set();
    lifecycle = emptyLifecycle();
    pendingRollbackId = null;
    loaded = false;
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
    if (rollback) selectRollbackRevision(Number(rollback.dataset.configRollback));
  }

  function initialize() {
    if (initialized) return;
    initialized = true;
    element("configCredentialForm").addEventListener("submit", (event) => {
      event.preventDefault();
      apiKey = element("configApiKey").value.trim();
      element("configApiKey").value = "";
      loaded = false;
      return load(true);
    });
    element("configWorkspace").addEventListener("click", handleWorkspaceClick);
    element("configPrefilterForm").addEventListener("submit", applyRule);
    element("configAssetForm").addEventListener("submit", applyAsset);
    element("configInternalCidrs").addEventListener("change", () => {
      workingDocuments.prefilter_policy.internal_cidrs = csvStrings(element("configInternalCidrs").value);
      selectedKind = "prefilter_policy";
      markDirty();
    });
    element("configRuleCancel").addEventListener("click", resetRuleForm);
    element("configAssetCancel").addEventListener("click", resetAssetForm);
    element("configForgetButton").addEventListener("click", forget);
    element("configReloadButton").addEventListener("click", () => {
      if (dirtyKinds.size && !global.confirm("Discard unsaved candidate changes and reload active configuration?")) return;
      load(true);
    });
    element("configCreateDraft").addEventListener("click", createDraft);
    element("configValidateDraft").addEventListener("click", validateDraft);
    element("configPreviewDraft").addEventListener("click", previewDraft);
    element("configActivateDraft").addEventListener("click", activateDraft);
    element("configConfirmActivate").addEventListener("change", renderLifecycle);
    element("configConfirmRollback").addEventListener("click", () => {
      if (pendingRollbackId != null) return rollbackRevision(pendingRollbackId);
    });
    element("configCancelRollback").addEventListener("click", cancelRollback);
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
    }),
  };
})(window);
