const API = "";
const PAGE_SIZE = 50;
const FILTER_KEYS = ["verdict", "signature", "model", "source", "review"];
const VALID_FILTERS = {
  verdict: new Set(["", "real", "false_positive", "uncertain"]),
  model: new Set(["", "llm", "prefilter"]),
  source: new Set(["", "suricata", "wazuh"]),
  review: new Set(["", "unreviewed", "agreed", "corrected"]),
};
// The model filter is the only one whose "no selection" is itself a product
// choice, so it is always written to the URL explicitly. Encoding All as an
// absent parameter made a bare URL ambiguous: a fresh /triage means Model (the
// default) while a Back to a bare entry would have meant All, silently
// changing the queue scope and the investigation neighbours. Internally All
// stays the empty string, and the empty string is what the API sees -- the
// model parameter is simply omitted from the request.
const SIGNATURE_FILTER_DEBOUNCE_MS = 300;
const MODEL_ALL_PARAM = "all";
const DEFAULT_MODEL_FILTER = "llm";
const TRIAGE_QUEUE_PATHS = new Set(["/", "/triage"]);

let currentFilter = {
  verdict: "",
  signature: "",
  model: "llm",
  source: "",
  review: "",
};
let mode = "local";
let focusedIndex = 0;
let unreviewedModelCount = 0;
let currentVerdicts = [];
let nextCursor = null;
let browsingHistory = false;
let pageLoading = false;
let timelineCache = { at: 0, data: [] };
let toastTimer = null;
let currentView = "triage";
let activeDetail = null;
let activeInvestigation = null;
// Detail and investigation are two awaits deep and race each other across
// navigations. Every navigation takes the next generation and aborts the
// previous one; a response may only touch the page if it still owns the
// current generation AND the URL still points at its event. Disabling the
// navigation buttons is not enough -- related-alert links, popstate, keyboard
// shortcuts and a slow network all produce the same overlap.
let detailGeneration = 0;
let detailAbort = null;
// The queue races the same way but on its own axis: a filter change, a live
// refresh and a Load Older page can all be in flight together. Kept separate
// from the detail generation so opening an alert never cancels a queue read
// and vice versa.
let queueGeneration = 0;
let queueAbort = null;

function formatHourLabel(isoHour) {
  const date = new Date(isoHour);
  if (Number.isNaN(date.getTime())) return isoHour;
  return date.toLocaleTimeString([], { hour: "numeric" });
}

function formatTimestamp(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString([], {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatRelativeAge(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return "Unknown";
  if (value < 60) return `${Math.round(value)}s ago`;
  if (value < 3600) return `${Math.round(value / 60)}m ago`;
  return `${(value / 3600).toFixed(1)}h ago`;
}

function formatCompact(value) {
  const number = Number(value ?? 0);
  return new Intl.NumberFormat(undefined, {
    notation: number >= 10_000 ? "compact" : "standard",
    maximumFractionDigits: number >= 10_000 ? 1 : 0,
  }).format(number);
}

// Drop a scheduled queue reload without touching the filter it was going to
// apply: the typed signature is already in currentFilter and in the URL.
function cancelSignatureFilterTimer() {
  clearTimeout(window.signatureFilterTimer);
  window.signatureFilterTimer = null;
}

function initializeView() {
  const viewByPath = {
    "/": "triage",
    "/triage": "triage",
    "/overview": "overview",
    "/behavioral": "behavioral",
    "/integrity": "integrity",
  };
  const detailMatch = window.location.pathname.match(/^\/triage\/(\d+)$/);
  currentView = detailMatch ? "detail" : (viewByPath[window.location.pathname] ?? "triage");
  const titles = {
    triage: "Triage queue",
    overview: "Overview",
    behavioral: "Behavioral signals",
    integrity: "Integrity",
    detail: "Alert detail",
  };

  document.querySelectorAll("[data-view]").forEach((panel) => {
    panel.hidden = panel.dataset.view !== currentView;
  });
  document.querySelectorAll("[data-view-link]").forEach((link) => {
    const activeView = currentView === "detail" ? "triage" : currentView;
    const active = link.dataset.viewLink === activeView;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  document.title = `${titles[currentView]} — Triagewall`;
  document.body.classList.remove("view-loading");
  // Every route transition funnels through here, so cancelling the pending
  // queue reload here covers direct navigation, keyboard shortcuts, related
  // alert links and popstate alike. Only the scheduled reload is dropped; the
  // typed signature stays in currentFilter and in the URL.
  if (currentView !== "triage") cancelSignatureFilterTimer();
  return detailMatch ? Number(detailMatch[1]) : null;
}

// Push every filter back onto the controls that display it.
function syncFilterControls() {
  document.getElementById("sigFilter").value = currentFilter.signature;
  document.getElementById("sourceFilter").value = currentFilter.source;
  document.getElementById("reviewFilter").value = currentFilter.review;
  document.getElementById("unreviewedQuickFilter").classList.toggle("active", currentFilter.review === "unreviewed");
  setActive(".filter-btn", "verdict", currentFilter.verdict);
  setActive(".model-btn", "model", currentFilter.model);
}

function readFilterParam(params, key) {
  const value = params.get(key);
  if (value == null) return null;
  if (key === "signature") return value.slice(0, 200);
  // An explicit All maps back onto the internal no-model-filter state.
  if (key === "model" && value === MODEL_ALL_PARAM) return "";
  return VALID_FILTERS[key]?.has(value) ? value : null;
}

// The URL is the whole truth, at first paint and on every history restore. A
// key the entry does not carry is cleared, so a filter chosen after that entry
// was recorded cannot survive into it and quietly narrow the queue. The one
// exception is `model`: a bare URL means the product default, Model, never
// All, which must always be written out as model=all.
function hydrateFilterStateFromUrl() {
  const params = new URLSearchParams(window.location.search);
  for (const key of FILTER_KEYS) {
    const value = readFilterParam(params, key);
    if (value != null) {
      currentFilter[key] = value;
    } else {
      currentFilter[key] = key === "model" ? DEFAULT_MODEL_FILTER : "";
    }
  }
  syncFilterControls();
}

function isTriageRoute() {
  return TRIAGE_QUEUE_PATHS.has(window.location.pathname) || detailPathEventId() != null;
}

// Stamp the default onto a bare triage URL so history can never record an
// entry whose model scope is only implied. replaceState, not pushState: this
// corrects the current entry rather than adding one. Other recognized filters
// and the event id in the pathname are preserved.
function canonicalizeTriageUrl() {
  if (!isTriageRoute()) return;
  const params = new URLSearchParams(window.location.search);
  if (params.get("model") != null) return;
  window.history.replaceState(
    {},
    "",
    `${window.location.pathname}?${queueFilterParams().toString()}`,
  );
}

// The queue filters travel with the analyst. Detail URLs, previous/next and
// the back link all carry them, so opening an alert and returning restores the
// view instead of resetting the queue.
// URL form of one filter. Only `model` differs from the internal value.
function filterParamValue(key) {
  if (key !== "model") return currentFilter[key];
  return currentFilter.model === "" ? MODEL_ALL_PARAM : currentFilter.model;
}

function queueFilterParams() {
  const params = new URLSearchParams();
  for (const key of FILTER_KEYS) {
    const value = filterParamValue(key);
    if (value) params.set(key, value);
  }
  return params;
}

function queueQueryString() {
  const query = queueFilterParams().toString();
  return query ? `?${query}` : "";
}

function detailPathEventId() {
  const match = window.location.pathname.match(/^\/triage\/(\d+)$/);
  return match ? Number(match[1]) : null;
}

// Retire the alert currently on screen the moment a new one is requested.
// pushState changes the URL immediately, so anything left interactive here
// belongs to the previous alert while the address bar names the next one --
// clicking Agree then writes feedback to the wrong event.
function retireActiveDetail() {
  activeDetail = null;
  activeInvestigation = null;
  const content = document.getElementById("detailPageContent");
  if (content) {
    content.innerHTML = '<div class="loading-state">Loading alert detail…</div>';
  }
  renderDetailNavigation(null);
}

function beginDetailNavigation() {
  detailGeneration += 1;
  if (detailAbort) detailAbort.abort();
  detailAbort = typeof AbortController === "function" ? new AbortController() : null;
  retireActiveDetail();
  return { generation: detailGeneration, signal: detailAbort?.signal };
}

// Invalidate outstanding detail work without starting any: used when leaving
// the detail view entirely.
function invalidateDetailNavigation() {
  detailGeneration += 1;
  if (detailAbort) detailAbort.abort();
  detailAbort = null;
}

function detailRequestIsCurrent(generation, eventId) {
  return generation === detailGeneration && detailPathEventId() === Number(eventId);
}

function beginQueueRequest() {
  queueGeneration += 1;
  if (queueAbort) queueAbort.abort();
  queueAbort = typeof AbortController === "function" ? new AbortController() : null;
  // The filter snapshot is part of the ticket: a response answers the filters
  // that were active when it was sent, not whatever they are when it lands.
  return {
    generation: queueGeneration,
    signal: queueAbort?.signal,
    filter: { ...currentFilter },
  };
}

function invalidateQueueRequests() {
  queueGeneration += 1;
  if (queueAbort) queueAbort.abort();
  queueAbort = null;
}

function queueRequestIsCurrent(request) {
  if (request.generation !== queueGeneration) return false;
  if (currentView !== "triage") return false;
  return FILTER_KEYS.every((key) => currentFilter[key] === request.filter[key]);
}

function syncQueueLinks() {
  document.querySelectorAll(".detail-back").forEach((link) => {
    link.setAttribute("href", `/triage${queueQueryString()}`);
  });
}

function syncUrlState(eventId = null) {
  if (window.location.pathname !== "/triage" && window.location.pathname !== "/") return;
  const url = new URL(window.location.href);
  for (const key of FILTER_KEYS) {
    const value = filterParamValue(key);
    if (value) url.searchParams.set(key, value);
    else url.searchParams.delete(key);
  }
  if (eventId == null) url.searchParams.delete("alert");
  else url.searchParams.set("alert", String(eventId));
  window.history.replaceState({}, "", `${url.pathname}${url.search}`);
}

function resetPagination() {
  nextCursor = null;
  browsingHistory = false;
  focusedIndex = 0;
}

function buildVerdictParams(cursor = null) {
  const params = new URLSearchParams();
  if (currentFilter.verdict) params.set("verdict", currentFilter.verdict);
  if (currentFilter.signature) params.set("signature", currentFilter.signature);
  // Internal values, not URL values: the API has no "all" model filter, so All
  // is expressed by omitting the parameter. Never send MODEL_ALL_PARAM here.
  if (currentFilter.model) params.set("model", currentFilter.model);
  if (currentFilter.source) params.set("source", currentFilter.source);
  if (currentFilter.review) params.set("review", currentFilter.review);
  params.set("limit", String(PAGE_SIZE));
  if (cursor) params.set("cursor", cursor);
  return params;
}

async function loadTimeline() {
  const now = Date.now();
  if (timelineCache.data.length && now - timelineCache.at < 60_000) {
    return timelineCache.data;
  }
  const response = await fetch(`${API}/api/v1/timeline`);
  if (!response.ok) throw new Error(`Timeline request failed (${response.status})`);
  const data = await response.json();
  const points = data.buckets ?? [];
  timelineCache = { at: now, data: points };
  return points;
}

function renderTimeline(points) {
  const host = document.getElementById("timelineChart");
  if (!host) return;
  if (!Array.isArray(points) || !points.length) {
    host.innerHTML = '<div class="empty-state">No activity recorded in this window.</div>';
    return;
  }

  const width = 960;
  const height = 278;
  const pad = { top: 14, right: 24, bottom: 34, left: 48 };
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;
  const totals = points.map((point) => Math.max(0, Number(point.total_alerts ?? 0)));
  const rates = points.map((point) => Math.min(100, Math.max(0, Number(point.prefilter_percentage ?? 0))));
  const maxTotal = Math.max(1, ...totals);
  const slot = plotWidth / Math.max(points.length, 1);
  const barWidth = Math.max(3, slot * 0.62);

  const grid = [0, 0.25, 0.5, 0.75, 1].map((fraction) => {
    const y = pad.top + plotHeight - plotHeight * fraction;
    const label = Math.round(maxTotal * fraction).toLocaleString();
    return `
      <line class="chart-grid" x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" />
      <text class="chart-axis-text" x="${pad.left - 9}" y="${y + 3}" text-anchor="end">${label}</text>`;
  }).join("");

  const bars = totals.map((total, index) => {
    const barHeight = total / maxTotal * plotHeight;
    const x = pad.left + slot * index + (slot - barWidth) / 2;
    const y = pad.top + plotHeight - barHeight;
    return `<rect class="chart-bar" x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${barWidth.toFixed(2)}" height="${Math.max(1, barHeight).toFixed(2)}" />`;
  }).join("");

  const linePoints = rates.map((rate, index) => {
    const x = pad.left + slot * index + slot / 2;
    const y = pad.top + plotHeight - rate / 100 * plotHeight;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");

  const labelEvery = Math.max(1, Math.ceil(points.length / 6));
  const labels = points.map((point, index) => {
    if (index % labelEvery !== 0 && index !== points.length - 1) return "";
    const x = pad.left + slot * index + slot / 2;
    return `<text class="chart-axis-text" x="${x.toFixed(2)}" y="${height - 8}" text-anchor="middle">${escapeHtml(formatHourLabel(point.timestamp))}</text>`;
  }).join("");

  const lastPoint = linePoints.split(" ").at(-1)?.split(",") ?? [];
  const endpoint = lastPoint.length === 2
    ? `<circle class="chart-point" cx="${lastPoint[0]}" cy="${lastPoint[1]}" r="3.5" />`
    : "";

  host.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-hidden="true">
      ${grid}
      ${bars}
      <polyline class="chart-line" points="${linePoints}" />
      ${endpoint}
      ${labels}
    </svg>`;
}

// Returns true when the response was applied, false when it was superseded.
async function loadVerdictPage(cursor = null, append = false, request = beginQueueRequest()) {
  // no-store: a cached row could present an already-reviewed alert as
  // unreviewed, which is exactly what the one-key agree action keys off.
  const response = await fetch(`${API}/api/v1/verdicts?${buildVerdictParams(cursor)}`, {
    cache: "no-store",
    signal: request.signal,
  });
  if (!queueRequestIsCurrent(request)) return false;
  if (!response.ok) throw new Error(`Decision request failed (${response.status})`);
  const data = await response.json();
  if (!queueRequestIsCurrent(request)) return false;
  mode = data.mode;
  nextCursor = data.next_cursor;
  currentVerdicts = append ? [...currentVerdicts, ...data.verdicts] : data.verdicts;
  document.getElementById("demoBanner").classList.toggle("hidden", mode !== "demo");
  renderVerdicts(currentVerdicts);
  renderPagination();
  return true;
}

// refreshDetail is false on scheduled polling ticks. Health and stats still
// refresh, but the detail DOM is left alone: replacing it would discard an
// unsaved operator note in #detailNotes. Explicit navigation, deep links and
// the post-feedback reload all pass through loadDetail directly.
async function load({ refreshDetail = true } = {}) {
  try {
    const healthResponse = await fetch(`${API}/api/health`);
    const health = await healthResponse.json();
    renderHealth(healthResponse.ok, health);
  } catch (_error) {
    renderHealth(false, { status: "unavailable" });
  }

  try {
    const statsResponse = await fetch(`${API}/api/v1/stats`);
    if (!statsResponse.ok) throw new Error(`Stats request failed (${statsResponse.status})`);
    const statsData = await statsResponse.json();
    mode = statsData.mode;
    renderStats(statsData.stats);
    document.getElementById("demoBanner").classList.toggle("hidden", mode !== "demo");
  } catch (error) {
    showToast(error.message, true);
  }

  if (currentView === "overview") {
    try {
      const points = await loadTimeline();
      renderTimeline(points);
      document.getElementById("timelineMeta").textContent = points.length ? `${points.length} hourly buckets` : "No activity";
    } catch (_error) {
      document.getElementById("timelineChart").innerHTML = '<div class="empty-state">Decision volume is temporarily unavailable.</div>';
      document.getElementById("timelineMeta").textContent = "Activity unavailable";
    }

  }

  if (currentView === "detail") {
    if (!refreshDetail) return;
    const detailId = Number(window.location.pathname.split("/").at(-1));
    await loadDetail(detailId);
  } else if (currentView === "triage" && !browsingHistory) {
    const request = beginQueueRequest();
    try {
      const applied = await loadVerdictPage(null, false, request);
      if (!applied) return;
      document.getElementById("freshness").textContent = `Live · ${new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
    } catch (error) {
      // A superseded or aborted queue read is not a failure to report.
      if (!queueRequestIsCurrent(request)) return;
      document.getElementById("freshness").textContent = "Decision feed unavailable";
      showToast(error.message, true);
    }
  } else if (currentView === "triage") {
    // Browsing history: the loaded pages are kept rather than refetched, but
    // they are repainted so a row corrected by a committed write is not left
    // showing its pre-commit state.
    renderVerdicts(currentVerdicts);
    renderPagination();
  }
}

function renderHealth(responseOk, health) {
  const age = Number(health.last_alert_age_seconds ?? Number.NaN);
  const isHealthy = responseOk && health.status === "ok";
  const isStale = !isHealthy;
  const label = isHealthy ? "Operational" : health.status === "stale" ? "Ingest stale" : "Unavailable";
  const ageLabel = formatRelativeAge(age);
  const storage = health.storage;

  document.getElementById("healthLabel").textContent = label;
  document.getElementById("lastSeen").textContent = ageLabel;
  document.getElementById("postureIngest").textContent = label;
  document.getElementById("postureIngest").className = isHealthy ? "ok" : "stale";
  document.getElementById("storageMeta").textContent = storage ? formatBytes(storage.total_on_disk_bytes) : "—";

  const healthDot = document.getElementById("healthDot");
  healthDot.classList.toggle("ok", isHealthy);
  healthDot.classList.toggle("stale", isStale);
  const livePulse = document.querySelector(".live-pulse");
  livePulse?.classList.toggle("ok", isHealthy);
  livePulse?.classList.toggle("stale", isStale);

  const banner = document.getElementById("staleBanner");
  const bannerText = document.getElementById("staleBannerText");
  banner.classList.toggle("hidden", isHealthy);
  if (!isHealthy) bannerText.textContent = Number.isFinite(age) ? `The latest event was processed ${ageLabel}.` : "The health endpoint could not confirm recent ingest.";
}

function renderStats(stats) {
  const real = Number(stats.real_ ?? stats.real ?? 0);
  const uncertain = Number(stats.unc ?? 0);
  const falsePositive = Number(stats.fp ?? 0);
  const policy = Number(stats.today_prefilter ?? 0);
  const model = Number(stats.today_llm ?? 0);
  const total = Number(stats.today_total ?? 0);
  const agreement = stats.reviewed ? Math.round(Number(stats.agreed ?? 0) / Number(stats.reviewed) * 100) : null;
  const policyRate = total ? Math.round(policy / total * 1000) / 10 : 0;

  document.getElementById("prefilterRate").textContent = policyRate.toFixed(1);
  document.getElementById("newDecisionCount").textContent = `${formatCompact(total)} total`;
  document.getElementById("policyCount").textContent = formatCompact(policy);
  document.getElementById("modelCount").textContent = formatCompact(model);
  document.getElementById("realCount").textContent = formatCompact(real);
  document.getElementById("falsePositiveCount").textContent = formatCompact(falsePositive);
  document.getElementById("uncertainCount").textContent = formatCompact(uncertain);
  document.getElementById("agreementRate").textContent = agreement === null ? "—" : `${agreement}%`;
  document.getElementById("agreementDetail").textContent = stats.reviewed ? `${formatCompact(stats.reviewed)} reviewed` : "No reviews in this window";
  document.getElementById("lifetimeTotal").textContent = formatCompact(stats.total ?? 0);
  document.getElementById("overviewLifetime").textContent = formatCompact(stats.total ?? 0);
  document.getElementById("policyBand").style.width = `${policyRate}%`;
  document.getElementById("modelBand").style.width = `${Math.max(0, 100 - policyRate)}%`;
  unreviewedModelCount = Number(stats.unreviewed_model_count ?? 0);
  document.getElementById("queueAllCount").textContent = formatCompact(model);
  document.getElementById("queueRealCount").textContent = formatCompact(stats.model_real_count ?? 0);
  document.getElementById("queueFalsePositiveCount").textContent = formatCompact(stats.model_fp_count ?? 0);
  document.getElementById("queueUncertainCount").textContent = formatCompact(stats.model_uncertain_count ?? 0);
  document.getElementById("queueUnreviewedCount").textContent = formatCompact(unreviewedModelCount);
  document.getElementById("sidebarQueueCount").textContent = formatCompact(unreviewedModelCount);
}

async function loadSpc() {
  try {
    const response = await fetch(`${API}/api/v1/spc-anomalies`);
    if (!response.ok) throw new Error("SPC request failed");
    renderSpc(await response.json());
  } catch (_error) {
    document.getElementById("spcPanel").classList.add("hidden");
  }
}

function renderSpc(data) {
  const panel = document.getElementById("spcPanel");
  const anomalies = data?.anomalies ?? [];
  if (data?.available === false || !anomalies.length) {
    panel.classList.add("hidden");
    return;
  }

  panel.classList.remove("hidden");
  document.getElementById("spcMeta").textContent = data.count_24h ? `${data.count_24h} in 24h` : `${anomalies.length} recorded`;
  document.getElementById("spcList").innerHTML = anomalies.map((anomaly) => {
    const timestamp = anomaly.detected_at
      ? new Date(anomaly.detected_at).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })
      : "";
    const feature = anomaly.feature === "alert_rate" ? "Rate deviation" : "Novel signature";
    const identity = anomaly.signature_id == null ? escapeHtml(anomaly.ip ?? "Unknown source") : `${escapeHtml(anomaly.ip ?? "Unknown source")} · SID ${escapeHtml(anomaly.signature_id)}`;
    return `
      <div class="signal-row">
        <span class="badge badge-signal">SPC</span>
        <div class="signal-copy">
          <strong>${feature} · ${identity}</strong>
          <small>${escapeHtml(anomaly.note ?? "Independent behavioral deviation detected")}</small>
        </div>
        <span class="signal-time">${escapeHtml(timestamp)}</span>
      </div>`;
  }).join("");
}

function renderPagination() {
  const pathLabel = currentFilter.model === "llm" ? "model-reviewed" : currentFilter.model === "prefilter" ? "policy-resolved" : "matching";
  // The loaded count describes this page; the unreviewed count is a global 24h
  // total from /stats, so it is labelled as such and never reads as a count of
  // what is currently filtered or paged in.
  const reviewLabel = `${formatCompact(unreviewedModelCount)} unreviewed in the last 24h, all filters`;
  document.getElementById("queueMeta").textContent = `${currentVerdicts.length} ${pathLabel} decisions loaded on this page · ${reviewLabel}`;
  document.getElementById("paginationMeta").textContent = browsingHistory
    ? `${currentVerdicts.length} loaded · live queue refresh paused while browsing history`
    : `${currentVerdicts.length} loaded · newest first`;
  const loadOlderButton = document.getElementById("loadOlderButton");
  loadOlderButton.classList.toggle("hidden", !nextCursor);
  loadOlderButton.disabled = pageLoading;
  loadOlderButton.textContent = pageLoading ? "Loading…" : `Load ${PAGE_SIZE} older`;
  document.getElementById("returnLiveButton").classList.toggle("hidden", !browsingHistory);
}

// Resolve the queue card an element belongs to, by stable event id.
function cardEventId(element) {
  const card = element?.closest?.("[data-event-id]");
  const eventId = Number(card?.dataset?.eventId);
  return Number.isInteger(eventId) && eventId > 0 ? eventId : null;
}

function findVerdictIndex(eventId) {
  if (!Number.isInteger(eventId) || eventId < 1) return -1;
  return currentVerdicts.findIndex((row) => Number(row.id) === eventId);
}

function renderVerdicts(list) {
  const host = document.getElementById("verdicts");
  // Capture two things before the markup is replaced: whether DOM focus is
  // genuinely inside the list, and which alert the logical selection points
  // at. Both travel by event id, so a refresh that reorders or inserts rows
  // cannot leave J/K/Enter aimed at a different alert, and focus is only ever
  // restored when it was already in the list -- never stolen from the search
  // box, the filters, or anything else.
  const active = document.activeElement;
  const focusWasInList = Boolean(
    host && active && typeof host.contains === "function" && host.contains(active),
  );
  const domFocusedEventId = focusWasInList ? cardEventId(active) : null;
  const selectedEventId = Number(currentVerdicts[focusedIndex]?.id ?? NaN);

  currentVerdicts = Array.isArray(list) ? list : [];

  const followed = findVerdictIndex(domFocusedEventId ?? selectedEventId);
  if (followed >= 0) focusedIndex = followed;
  if (focusedIndex >= currentVerdicts.length) focusedIndex = Math.max(0, currentVerdicts.length - 1);

  if (!currentVerdicts.length) {
    document.getElementById("verdicts").innerHTML = `
      <div class="empty-card">
        <div><strong>No decisions match this view.</strong><span>Adjust the filters or wait for the next event. An empty model queue often means deterministic policy is resolving routine traffic.</span></div>
      </div>`;
    return;
  }

  document.getElementById("verdicts").innerHTML = currentVerdicts.map((verdict, index) => {
    const sensor = verdict.sensor_context?.source ?? "suricata";
    const ruleLabel = sensor === "wazuh" ? "Rule" : "SID";
    const agent = verdict.sensor_context?.agent;
    const timestampValue = verdict.timestamp ?? verdict.processed_at;
    const timestamp = timestampValue
      ? new Date(timestampValue).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })
      : "—";
    const source = verdict.src_ip ?? (agent?.name ? `Agent ${agent.name}` : "—");
    const destination = verdict.dest_ip ?? "—";
    const confidence = Number(verdict.confidence ?? 0);
    const reviewedLabel = verdict.human_verdict
      ? ` · ${verdict.agreed ? "agreed" : "corrected"}`
      : "";

    return `
      <article class="decision-card verdict-${escapeHtml(verdict.verdict)} ${index === focusedIndex ? "focused" : ""}" data-idx="${index}" data-event-id="${Number(verdict.id)}" tabindex="0" aria-label="Open alert details for ${escapeHtml(verdict.signature ?? "unnamed alert")}">
        <time class="queue-time">${escapeHtml(timestamp)}</time>
        <div class="queue-signature">
          <strong>${escapeHtml(verdict.signature ?? "Unnamed alert")}</strong>
          <span class="queue-rule"><span class="badge badge-sensor">${escapeHtml(sensor)}</span> ${ruleLabel} ${escapeHtml(verdict.signature_id ?? "?")}</span>
        </div>
        <span class="queue-endpoint queue-source">${escapeHtml(source)}</span>
        <span class="queue-endpoint queue-destination">${escapeHtml(destination)}</span>
        <span class="badge badge-${escapeHtml(verdict.verdict)} queue-verdict" title="${escapeHtml(reviewedLabel.trim())}">${escapeHtml(String(verdict.verdict ?? "unknown").replace("_", " "))}</span>
        <span class="queue-confidence">${Number.isFinite(confidence) ? confidence.toFixed(2) : "—"}</span>
      </article>`;
  }).join("");

  // Put keyboard focus back on the same alert. If it is gone from the results,
  // focus nothing rather than an unrelated card.
  if (domFocusedEventId == null) return;
  if (findVerdictIndex(domFocusedEventId) < 0) return;
  const card = host?.querySelector?.(`[data-event-id="${domFocusedEventId}"]`);
  card?.focus?.({ preventScroll: true });
}

function renderAssets(assetContext) {
  const entries = [
    ["Source", assetContext?.source],
    ["Destination", assetContext?.destination],
  ].filter(([, asset]) => asset?.hostname);
  if (!entries.length) return "";
  return `<div class="asset-row">${entries.map(([side, asset]) => `
    <span class="asset-chip"><strong>${side}</strong> ${escapeHtml(asset.hostname)} · ${escapeHtml(asset.role ?? "asset")} · ${escapeHtml(asset.criticality ?? "unknown")}</span>`).join("")}</div>`;
}

function shortModelName(value) {
  if (!value) return "Local model";
  const text = String(value);
  if (text.length <= 24) return text;
  const tail = text.split("/").at(-1) ?? text;
  return tail.length <= 24 ? tail : "Local model";
}

function detailField(label, value) {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value ?? "—")}</dd></div>`;
}

function prettyRawAlert(rawAlert) {
  if (!rawAlert) return null;
  try {
    return JSON.stringify(JSON.parse(rawAlert), null, 2);
  } catch (_error) {
    return String(rawAlert);
  }
}

function parseRawAlert(rawAlert) {
  if (!rawAlert) return null;
  try {
    const parsed = JSON.parse(rawAlert);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch (_error) {
    return null;
  }
}

// Reads one scalar out of the stored sensor record. Objects and arrays are
// rejected so a nested structure can never be stringified into a field that
// claims to be a single recorded value.
function readRawScalar(source, path) {
  let value = source;
  for (const key of path) {
    if (value === null || typeof value !== "object") return null;
    value = value[key];
  }
  if (value === null || value === undefined || typeof value === "object") return null;
  return value;
}

function readRawList(source, path, maximum = 8) {
  let value = source;
  for (const key of path) {
    if (value === null || typeof value !== "object") return null;
    value = value[key];
  }
  if (!Array.isArray(value)) return null;
  const items = value.filter((item) => item !== null && typeof item !== "object");
  if (!items.length) return null;
  const shown = items.slice(0, maximum).join(", ");
  return items.length > maximum ? `${shown} (+${items.length - maximum} more)` : shown;
}

// Distinct from detailField: an absent derived value is stated as unrecorded
// rather than shown as an em dash, so the page never implies a blank means the
// sensor reported nothing.
function derivedField(label, value) {
  const missing = value === null || value === undefined || value === "";
  return `<div><dt>${escapeHtml(label)}</dt><dd${missing ? ' class="derived-missing"' : ""}>${escapeHtml(missing ? "Not recorded" : value)}</dd></div>`;
}

// Wazuh manager/location/decoder/groups and the Suricata flow envelope are not
// columns; they exist only inside the retained sensor record. They are read
// from the record this response already returned, so demo mode and IP
// redaction — which withhold raw_alert — degrade to "not available" instead of
// disclosing anything the verdict row would not.
function renderSourceContext(verdict, sensor) {
  const title = sensor === "wazuh" ? "Wazuh rule context" : "Suricata flow context";
  const raw = parseRawAlert(verdict.raw_alert);
  if (!raw) {
    return `
      <section class="detail-section">
        <h3>${escapeHtml(title)}</h3>
        <p class="detail-empty">Not available. This response does not include the original sensor record, so these fields cannot be derived.</p>
      </section>`;
  }
  const fields = sensor === "wazuh"
    ? [
      ["Rule ID", readRawScalar(raw, ["rule", "id"])],
      ["Rule level", readRawScalar(raw, ["rule", "level"])],
      ["Rule groups", readRawList(raw, ["rule", "groups"])],
      ["Agent ID", verdict.sensor_context?.agent?.id ?? readRawScalar(raw, ["agent", "id"])],
      ["Agent name", verdict.sensor_context?.agent?.name ?? readRawScalar(raw, ["agent", "name"])],
      ["Manager", readRawScalar(raw, ["manager", "name"])],
      ["Location", readRawScalar(raw, ["location"])],
      ["Decoder", readRawScalar(raw, ["decoder", "name"])],
      ["Parent decoder", readRawScalar(raw, ["decoder", "parent"])],
    ]
    : [
      ["Flow ID", readRawScalar(raw, ["flow_id"])],
      ["Interface", readRawScalar(raw, ["in_iface"])],
      ["Packet source", readRawScalar(raw, ["pkt_src"])],
      ["Application protocol", readRawScalar(raw, ["app_proto"])],
      ["Rule action", readRawScalar(raw, ["alert", "action"])],
      ["Rule revision", readRawScalar(raw, ["alert", "rev"])],
      ["Rule GID", readRawScalar(raw, ["alert", "gid"])],
    ];
  return `
    <section class="detail-section">
      <h3>${escapeHtml(title)}</h3>
      <dl class="detail-grid detail-facts">${fields.map(([label, value]) => derivedField(label, value)).join("")}</dl>
    </section>`;
}

function relatedScopeNote(group, windowHours) {
  if (group.exact) {
    return `Exact match across the last ${windowHours}h.`;
  }
  const examined = formatCompact(group.candidates_examined ?? 0);
  if (group.truncated) {
    return `Partial: only the ${examined} newest events in the last ${windowHours}h were examined, so older matches in this window are not shown.`;
  }
  return `Matched across ${examined} events in the last ${windowHours}h.`;
}

function renderRelatedAlert(alert) {
  const verdictLabel = String(alert.verdict ?? "unknown").replace("_", " ");
  const endpoints = `${alert.src_ip ?? "—"} → ${alert.dest_ip ?? "—"}`;
  return `
    <a class="related-row" href="/triage/${Number(alert.id)}${queueQueryString()}" data-related-id="${Number(alert.id)}">
      <span class="badge badge-${escapeHtml(alert.verdict)}">${escapeHtml(verdictLabel)}</span>
      <span class="related-signature">${escapeHtml(alert.signature ?? "Unnamed alert")}</span>
      <span class="related-endpoint">${escapeHtml(endpoints)}</span>
      <time class="related-time">${escapeHtml(formatTimestamp(alert.processed_at))}</time>
    </a>`;
}

function renderRecurrence(data) {
  const host = document.getElementById("recurrencePanel");
  if (!host) return;
  const recurrence = data?.recurrence;
  if (!recurrence?.available) {
    host.innerHTML = `
      <h3>Recurrence</h3>
      <p class="detail-empty">Not recorded. This event carries no signature identifier, so it has no recurrence group.</p>`;
    return;
  }
  const ruleLabel = recurrence.source_type === "wazuh" ? "rule" : "signature";
  host.innerHTML = `
    <h3>Recurrence</h3>
    <p class="recurrence-headline"><strong>${escapeHtml(formatCompact(recurrence.occurrences))}</strong> in the last ${escapeHtml(data.window_hours)}h</p>
    <p class="recurrence-basis">Grouped by source type and ${escapeHtml(ruleLabel)} ID (${escapeHtml(recurrence.source_type ?? "unknown")} · ${escapeHtml(recurrence.signature_id)}). Suricata and Wazuh identifiers are counted separately.</p>
    <dl class="detail-grid recurrence-stats">
      ${detailField("First in window", formatTimestamp(recurrence.first_seen))}
      ${detailField("Latest in window", formatTimestamp(recurrence.last_seen))}
      ${detailField("Real", formatCompact(recurrence.real_count))}
      ${detailField("False positive", formatCompact(recurrence.false_positive_count))}
      ${detailField("Uncertain", formatCompact(recurrence.uncertain_count))}
      ${detailField("Unclassified", formatCompact(recurrence.unclassified_count))}
    </dl>`;
}

function renderRelated(data) {
  const host = document.getElementById("relatedPanel");
  if (!host) return;
  const groups = Array.isArray(data?.related) ? data.related : [];
  host.innerHTML = `
    <h3>Related activity</h3>
    ${groups.map((group) => `
      <div class="related-group">
        <div class="related-group-head">
          <strong>${escapeHtml(group.label)}</strong>
          <span class="related-count">${escapeHtml(formatCompact(group.alerts?.length ?? 0))} shown</span>
        </div>
        <p class="related-reason">${escapeHtml(group.reason)}</p>
        <p class="related-scope${group.truncated ? " related-scope-partial" : ""}">${escapeHtml(relatedScopeNote(group, data.window_hours))}</p>
        ${group.alerts?.length
          ? `<div class="related-list">${group.alerts.map(renderRelatedAlert).join("")}</div>`
          : '<p class="detail-empty">No other alerts matched in this window.</p>'}
      </div>`).join("")}`;
}

function renderInvestigation(data) {
  renderRecurrence(data);
  renderRelated(data);
}

function renderInvestigationUnavailable() {
  const message = '<p class="detail-empty">Related activity is temporarily unavailable.</p>';
  const recurrenceHost = document.getElementById("recurrencePanel");
  const relatedHost = document.getElementById("relatedPanel");
  if (recurrenceHost) recurrenceHost.innerHTML = `<h3>Recurrence</h3>${message}`;
  if (relatedHost) relatedHost.innerHTML = `<h3>Related activity</h3>${message}`;
}

function renderDetail(verdict) {
  activeDetail = verdict;
  const sensor = verdict.sensor_context?.source ?? "suricata";
  const agent = verdict.sensor_context?.agent;
  const rawAlert = prettyRawAlert(verdict.raw_alert);
  const confidence = Math.min(100, Math.max(0, Math.round(Number(verdict.confidence ?? 0) * 100)));
  const sourceAsset = verdict.asset_context?.source;
  const destinationAsset = verdict.asset_context?.destination;
  const isPolicy = verdict.model_used === "prefilter";
  const reviewSection = verdict.human_verdict
    ? `<section class="analysis-section">
        <h3>Operator review</h3>
        <dl class="detail-grid">
          ${detailField("Decision", verdict.agreed ? "Agreed" : "Corrected")}
          ${detailField("Human verdict", verdict.human_verdict)}
          ${detailField("Reviewed at", formatTimestamp(verdict.reviewed_at))}
          ${detailField("Notes", verdict.human_notes || "No note recorded")}
        </dl>
      </section>`
    : mode === "demo"
      ? '<section class="analysis-section"><h3>Operator review</h3><p class="detail-empty">Feedback is disabled in demo mode.</p></section>'
      : `<section class="analysis-section">
          <h3>Operator review</h3>
          <label class="detail-note-label" for="detailNotes">Optional note
            <textarea id="detailNotes" maxlength="2000" placeholder="Record the reason for this review"></textarea>
          </label>
          <div class="detail-feedback-actions">
            <button class="action-btn action-primary" type="button" data-detail-feedback="${escapeHtml(verdict.verdict)}">Agree with ${escapeHtml(String(verdict.verdict).replace("_", " "))}</button>
            <button class="action-btn" type="button" data-detail-feedback="real">Mark real</button>
            <button class="action-btn" type="button" data-detail-feedback="false_positive">Mark false positive</button>
            <button class="action-btn" type="button" data-detail-feedback="uncertain">Mark uncertain</button>
          </div>
        </section>`;

  const currentBoundary = isPolicy
    ? `<li><span class="integrity-check">✓</span><div><strong>Model bypassed</strong><small>Deterministic policy resolved this event without an LLM call.</small></div></li>`
    : `<li><span class="integrity-check">✓</span><div><strong>Canary response check</strong><small>Current classifier scans raw and decoded model output.</small></div></li>
       <li><span class="integrity-check">✓</span><div><strong>Strict response contract</strong><small>Only the complete three-field JSON schema is accepted.</small></div></li>
       <li><span class="integrity-check">✓</span><div><strong>${sensor === "wazuh" ? "Bounded Wazuh projection" : "Fail-closed Suricata isolation"}</strong><small>Current source-specific model boundary.</small></div></li>`;

  document.getElementById("detailPageContent").innerHTML = `
    <div class="detail-page-grid">
      <article class="detail-evidence-column">
        <div class="detail-event-meta">
          <span class="badge badge-${escapeHtml(verdict.verdict)}">${escapeHtml(String(verdict.verdict ?? "unknown").replace("_", " "))}</span>
          <span>${escapeHtml(formatTimestamp(verdict.timestamp))}</span>
          <span>${sensor === "wazuh" ? "RULE" : "SID"} ${escapeHtml(verdict.signature_id ?? "—")}</span>
        </div>
        <h1 id="alert-page-title">${escapeHtml(verdict.signature ?? "Unnamed alert")}</h1>

        <dl class="endpoint-grid">
          ${detailField("Source", verdict.src_ip ? `${verdict.src_ip}:${verdict.src_port ?? "?"}` : agent?.name ?? agent?.id)}
          ${detailField("Destination", verdict.dest_ip ? `${verdict.dest_ip}:${verdict.dest_port ?? "?"}` : null)}
          ${detailField("Protocol", verdict.proto)}
          ${detailField("Source type", sensor)}
        </dl>

        <section class="detail-section">
          <h3>Decision context</h3>
          <dl class="detail-grid detail-facts">
            ${detailField("Category", verdict.category)}
            ${detailField("Severity", verdict.severity)}
            ${detailField("Processed", formatTimestamp(verdict.processed_at))}
            ${detailField("Database event ID", verdict.id)}
            ${detailField("Source instance", verdict.sensor_context?.instance)}
            ${detailField("Source event ID", verdict.sensor_context?.event_id)}
            ${detailField("Source asset", sourceAsset?.hostname ? `${sourceAsset.hostname} · ${sourceAsset.role ?? "asset"} · ${sourceAsset.criticality ?? "unknown"}` : null)}
            ${detailField("Destination asset", destinationAsset?.hostname ? `${destinationAsset.hostname} · ${destinationAsset.role ?? "asset"} · ${destinationAsset.criticality ?? "unknown"}` : null)}
          </dl>
        </section>

        ${renderSourceContext(verdict, sensor)}

        <section class="detail-section" id="relatedPanel">
          <h3>Related activity</h3>
          <p class="detail-empty">Loading related activity…</p>
        </section>

        <section class="detail-section raw-section">
          <div class="raw-head">
            <div><h3>Original sensor record</h3><p>Stored source evidence. The exact protected model projection is not persisted.</p></div>
            ${rawAlert ? '<button id="copyRawButton" class="text-button" type="button">Copy JSON</button>' : ""}
          </div>
          ${rawAlert ? `<pre class="raw-event">${escapeHtml(rawAlert)}</pre>` : '<p class="detail-empty">Original sensor record unavailable for this record.</p>'}
        </section>
      </article>

      <aside class="detail-analysis-column">
        <section class="model-verdict-panel">
          <span class="analysis-label">${isPolicy ? "POLICY VERDICT" : "MODEL VERDICT"}</span>
          <div class="verdict-score"><strong class="verdict-color-${escapeHtml(verdict.verdict)}">${escapeHtml(String(verdict.verdict ?? "unknown").replace("_", " "))}</strong><span>confidence ${(confidence / 100).toFixed(2)}</span></div>
          <div class="confidence-track"><span style="width:${confidence}%"></span></div>
          <p class="model-meta">${escapeHtml(shortModelName(verdict.model_used))}</p>
        </section>

        <section class="analysis-section" id="recurrencePanel">
          <h3>Recurrence</h3>
          <p class="detail-empty">Loading recurrence…</p>
        </section>

        <section class="analysis-section">
          <h3>Reasoning</h3>
          <p class="analysis-reasoning">${escapeHtml(verdict.reasoning ?? "No reasoning recorded.")}</p>
        </section>

        <section class="analysis-section">
          <h3>Current model boundary</h3>
          <ul class="detail-integrity-list">${currentBoundary}</ul>
          <p class="boundary-note">This is current classifier posture, not a per-event attestation for historical rows.</p>
        </section>

        ${reviewSection}
      </aside>
    </div>`;

  document.title = `${verdict.signature ?? "Alert detail"} — Triagewall`;
  renderDetailNavigation(null);
}

// Neighbours come from the server against the active queue filters, so they
// stay correct on a deep link or refresh, where no queue page has been loaded.
function renderDetailNavigation(neighbors) {
  const previous = neighbors?.previous ?? null;
  const next = neighbors?.next ?? null;
  const previousButton = document.getElementById("previousAlertButton");
  const nextButton = document.getElementById("nextAlertButton");
  previousButton.disabled = !previous;
  nextButton.disabled = !next;
  previousButton.dataset.eventId = previous?.id ?? "";
  nextButton.dataset.eventId = next?.id ?? "";
  previousButton.title = previous?.signature ? `Previous: ${previous.signature}` : "";
  nextButton.title = next?.signature ? `Next: ${next.signature}` : "";
}

async function loadInvestigation(eventId, navigation) {
  const { generation, signal } = navigation;
  const params = new URLSearchParams();
  for (const key of FILTER_KEYS) {
    // Internal values: All omits the model parameter rather than sending it.
    if (currentFilter[key]) params.set(key, currentFilter[key]);
  }
  try {
    const response = await fetch(
      `${API}/api/v1/verdicts/${eventId}/investigation?${params}`,
      { cache: "no-store", signal },
    );
    if (!detailRequestIsCurrent(generation, eventId)) return;
    if (!response.ok) throw new Error(`Investigation request failed (${response.status})`);
    const data = await response.json();
    if (!detailRequestIsCurrent(generation, eventId)) return;
    activeInvestigation = data;
    renderInvestigation(data);
    renderDetailNavigation(data.neighbors);
  } catch (_error) {
    // A superseded or aborted request stays silent: it must not blank the
    // panels or clear the neighbour targets belonging to the alert now shown.
    if (!detailRequestIsCurrent(generation, eventId)) return;
    activeInvestigation = null;
    renderInvestigationUnavailable();
    renderDetailNavigation(null);
  }
}

async function loadDetail(eventId, navigation = beginDetailNavigation()) {
  if (!Number.isInteger(eventId) || eventId < 1) return;
  const { generation, signal } = navigation;
  syncQueueLinks();
  try {
    // no-store: a reload after saving feedback must never be answered from a
    // cached pre-feedback response.
    const response = await fetch(`${API}/api/v1/verdicts/${eventId}`, {
      cache: "no-store",
      signal,
    });
    if (!detailRequestIsCurrent(generation, eventId)) return;
    if (!response.ok) throw new Error(response.status === 404 ? "Alert not found." : `Alert request failed (${response.status})`);
    const data = await response.json();
    if (!detailRequestIsCurrent(generation, eventId)) return;
    mode = data.mode;
    document.getElementById("demoBanner").classList.toggle("hidden", mode !== "demo");
    renderDetail(data.verdict);
  } catch (error) {
    if (!detailRequestIsCurrent(generation, eventId)) return;
    activeInvestigation = null;
    document.getElementById("detailPageContent").innerHTML = `<div class="empty-card"><div><strong>${escapeHtml(error.message)}</strong><span>Return to the queue and choose another alert.</span></div></div>`;
    renderDetailNavigation(null);
    return;
  }
  await loadInvestigation(eventId, navigation);
}

async function openDetailById(eventId, { focusNotes = false } = {}) {
  if (!Number.isInteger(eventId) || eventId < 1) return;
  // Push first so the generation check below compares against the new URL.
  window.history.pushState({}, "", `/triage/${eventId}${queueQueryString()}`);
  initializeView();
  window.scrollTo({ top: 0, behavior: "instant" });
  const navigation = beginDetailNavigation();
  await loadDetail(eventId, navigation);
  // The review controls only exist once the detail body has rendered, and only
  // if this navigation is still the one on screen.
  if (focusNotes && detailRequestIsCurrent(navigation.generation, eventId)) {
    document.getElementById("detailNotes")?.focus();
  }
}

function openDetail(verdict) {
  if (!verdict) return;
  openDetailById(Number(verdict.id));
}

function closeDetail() {
  invalidateDetailNavigation();
  activeDetail = null;
  activeInvestigation = null;
  window.history.pushState({}, "", `/triage${queueQueryString()}`);
  initializeView();
  load();
}

function focusAlert(index) {
  focusedIndex = index;
  document.querySelectorAll("[data-idx]").forEach((element) => {
    element.classList.toggle("focused", Number(element.dataset.idx) === index);
  });
}

function toggleCorrection(eventId, trigger) {
  const panel = document.getElementById(`correction-${eventId}`);
  if (!panel) return;
  const expanded = panel.classList.toggle("hidden") === false;
  trigger?.setAttribute("aria-expanded", String(expanded));
}

// Patch a committed review onto the loaded rows. A queue read taken before
// the write committed still shows the row as unreviewed, and the one-key
// agree action keys off exactly that field, so leaving it stale invites a
// second write that would replace the saved note with an empty one.
function applySavedFeedback(eventId, humanVerdict, notes) {
  currentVerdicts = currentVerdicts.map((row) => {
    if (Number(row.id) !== eventId) return row;
    return {
      ...row,
      human_verdict: humanVerdict,
      human_notes: notes,
      agreed: row.verdict === humanVerdict ? 1 : 0,
    };
  });
}

async function reconcileQueueAfterFeedback() {
  // Retire any queue read issued before the commit: letting it land would
  // repaint the row as unreviewed again.
  invalidateQueueRequests();
  if (browsingHistory) {
    // The loaded historical pages are the operator's context. Repaint the
    // patched row instead of discarding them; the next live refresh takes the
    // server's version.
    renderVerdicts(currentVerdicts);
    renderPagination();
    return;
  }
  resetPagination();
  await load();
}

// One write per event at a time. While a POST is in flight the row it belongs
// to can still look unreviewed, and a second submit would race the first.
const pendingFeedback = new Set();

async function feedback(id, agentVerdict, customVerdict = null, notes = "") {
  const humanVerdict = customVerdict || agentVerdict;
  const eventId = Number(id);
  // Write-side guard, before anything is reserved or sent. A control left over
  // from a previous alert must not be able to write to it once the URL has
  // moved on, and a missing id must never reach /feedback/NaN.
  if (!Number.isInteger(eventId) || eventId < 1) return;
  if (currentView === "detail" && detailPathEventId() !== eventId) return;
  if (pendingFeedback.has(eventId)) return;
  pendingFeedback.add(eventId);
  try {
    // The write is never aborted: a save that reached the server must not be
    // cancelled because the operator moved on.
    const response = await fetch(`${API}/api/v1/feedback/${eventId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ human_verdict: humanVerdict, notes }),
    });
    if (!response.ok) throw new Error(`Feedback was not saved (${response.status})`);
    showToast("Operator feedback saved.");
    // The server has committed, so the in-memory row is corrected wherever the
    // operator now is. Route ownership decides what may be re-rendered, not
    // whether the write is recorded.
    applySavedFeedback(eventId, humanVerdict, notes);
    if (currentView === "detail") {
      // Only the alert this write belongs to may be reloaded. Another detail
      // page has its own unsaved draft to protect.
      if (detailPathEventId() === eventId) {
        await loadDetail(eventId, beginDetailNavigation());
      }
      return;
    }
    if (currentView === "triage") {
      // Reconcile even when the write was raised from a detail page the
      // operator has already left.
      await reconcileQueueAfterFeedback();
    }
  } catch (error) {
    // Route ownership guards DOM reloads, not write-result notifications.
    // Navigating away must never hide that a review failed to save, so this
    // names the alert and reports wherever the operator is.
    showToast(`Alert ${eventId}: ${error.message}`, true);
  } finally {
    pendingFeedback.delete(eventId);
  }
}

async function loadOlder() {
  if (!nextCursor || pageLoading) return;
  const cursor = nextCursor;
  const request = beginQueueRequest();
  // History mode is taken transactionally. Claiming it now stops a polling
  // refresh from superseding the page being fetched, and a failure hands back
  // exactly what was taken: a failed first page returns to live, while a
  // failed later page stays in history because earlier rows are still loaded.
  const wasBrowsingHistory = browsingHistory;
  let appended = false;
  pageLoading = true;
  browsingHistory = true;
  renderPagination();
  try {
    appended = await loadVerdictPage(cursor, true, request);
  } catch (error) {
    if (queueRequestIsCurrent(request)) showToast(error.message, true);
  } finally {
    pageLoading = false;
    // If the filters moved on, the newer request owns the rendering; appending
    // this page or repainting from it would splice old-filter rows into it.
    if (queueRequestIsCurrent(request)) {
      if (!appended) browsingHistory = wasBrowsingHistory;
      renderPagination();
    }
  }
}

async function returnToLive() {
  resetPagination();
  await load();
}

function applyFilters() {
  // Queue-only. The signature filter is debounced, so this can fire after the
  // operator has already opened an alert; load() would then remount the detail
  // page and discard an unsaved note. The filter value itself is already in
  // currentFilter and in the detail URL, and openDetailById loads the
  // investigation with it, so there is nothing for a stale call to do here.
  if (currentView !== "triage") return;
  // Retire any queue read already in flight, including a Load Older page whose
  // rows belong to the filters being replaced.
  invalidateQueueRequests();
  resetPagination();
  syncUrlState();
  syncQueueLinks();
  load();
}

function showToast(message, isError = false) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3200);
}

function setActive(selector, dataKey, value) {
  document.querySelectorAll(selector).forEach((button) => {
    button.classList.toggle("active", button.dataset[dataKey] === value);
  });
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

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const digits = unit === 0 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${units[unit]}`;
}

document.querySelectorAll(".filter-btn").forEach((button) => {
  button.addEventListener("click", () => {
    currentFilter.verdict = button.dataset.verdict;
    setActive(".filter-btn", "verdict", currentFilter.verdict);
    applyFilters();
  });
});

document.querySelectorAll(".model-btn").forEach((button) => {
  button.addEventListener("click", () => {
    currentFilter.model = button.dataset.model;
    setActive(".model-btn", "model", currentFilter.model);
    applyFilters();
  });
});

document.getElementById("sigFilter").addEventListener("input", (event) => {
  currentFilter.signature = event.target.value;
  cancelSignatureFilterTimer();
  window.signatureFilterTimer = setTimeout(applyFilters, SIGNATURE_FILTER_DEBOUNCE_MS);
});

document.getElementById("sourceFilter").addEventListener("change", (event) => {
  currentFilter.source = event.target.value;
  applyFilters();
});

document.getElementById("reviewFilter").addEventListener("change", (event) => {
  currentFilter.review = event.target.value;
  document.getElementById("unreviewedQuickFilter").classList.toggle("active", currentFilter.review === "unreviewed");
  applyFilters();
});

document.getElementById("filterToggleButton").addEventListener("click", (event) => {
  const filters = document.getElementById("advancedFilters");
  const expanded = event.currentTarget.getAttribute("aria-expanded") === "true";
  filters.classList.toggle("hidden", expanded);
  event.currentTarget.setAttribute("aria-expanded", String(!expanded));
});

document.getElementById("unreviewedQuickFilter").addEventListener("click", () => {
  currentFilter.review = currentFilter.review === "unreviewed" ? "" : "unreviewed";
  document.getElementById("reviewFilter").value = currentFilter.review;
  document.getElementById("unreviewedQuickFilter").classList.toggle("active", currentFilter.review === "unreviewed");
  applyFilters();
});

document.getElementById("loadOlderButton").addEventListener("click", loadOlder);
document.getElementById("returnLiveButton").addEventListener("click", returnToLive);

document.getElementById("detailPageContent").addEventListener("click", async (event) => {
  const feedbackButton = event.target.closest("[data-detail-feedback]");
  if (feedbackButton) {
    // Refuse a click on controls belonging to an alert that is no longer the
    // routed one; feedback() repeats the check on the write side.
    const eventId = Number(activeDetail?.id);
    if (!Number.isInteger(eventId) || eventId < 1) return;
    if (detailPathEventId() !== eventId) return;
    const notes = document.getElementById("detailNotes")?.value ?? "";
    await feedback(eventId, activeDetail?.verdict, feedbackButton.dataset.detailFeedback, notes);
    return;
  }
  const relatedRow = event.target.closest("[data-related-id]");
  if (relatedRow) {
    event.preventDefault();
    openDetailById(Number(relatedRow.dataset.relatedId));
    return;
  }
  if (event.target.closest("#copyRawButton")) {
    const rawAlert = prettyRawAlert(activeDetail?.raw_alert);
    if (!rawAlert) return;
    try {
      await navigator.clipboard.writeText(rawAlert);
      showToast("Raw event copied.");
    } catch (_error) {
      showToast("Clipboard access was unavailable.", true);
    }
  }
});

document.querySelectorAll("#previousAlertButton, #nextAlertButton").forEach((button) => {
  button.addEventListener("click", () => {
    openDetailById(Number(button.dataset.eventId));
  });
});

window.addEventListener("popstate", () => {
  // Rebuild the filters from the restored URL before anything reads them, so
  // the restored route, its investigation request, previous/next and the back
  // link all use that entry's filters rather than the newer in-memory ones.
  hydrateFilterStateFromUrl();
  canonicalizeTriageUrl();
  syncQueueLinks();
  const detailId = initializeView();
  if (detailId) {
    loadDetail(detailId, beginDetailNavigation());
  } else {
    // Leaving the detail view must retire any request still in flight.
    invalidateDetailNavigation();
    invalidateQueueRequests();
    activeDetail = null;
    activeInvestigation = null;
    resetPagination();
    load();
  }
});

// Tab moves DOM focus without going through focusAlert, so keep focusedIndex
// in step: otherwise Enter would open whichever card the arrow keys last
// touched rather than the one the operator is actually on.
document.getElementById("verdicts").addEventListener("focusin", (event) => {
  const card = event.target.closest("[data-idx]");
  if (card) focusAlert(Number(card.dataset.idx));
});

document.getElementById("verdicts").addEventListener("click", (event) => {
  const feedbackButton = event.target.closest("[data-feedback]");
  if (feedbackButton) {
    event.stopPropagation();
    const eventId = Number(feedbackButton.dataset.eventId);
    if (feedbackButton.dataset.feedback === "agree") {
      feedback(eventId, feedbackButton.dataset.agentVerdict);
    } else if (feedbackButton.dataset.feedback === "toggle") {
      toggleCorrection(eventId, feedbackButton);
    } else if (feedbackButton.dataset.feedback === "choice") {
      feedback(eventId, null, feedbackButton.dataset.choice);
    }
    return;
  }
  const card = event.target.closest("[data-idx]");
  if (card) {
    const index = Number(card.dataset.idx);
    focusAlert(index);
    openDetail(currentVerdicts[index]);
  }
});

document.addEventListener("keydown", (event) => {
  if (["INPUT", "BUTTON", "SELECT", "TEXTAREA"].includes(event.target.tagName)) return;
  const key = event.key.toLowerCase();
  if (currentView === "detail") {
    if (key === "escape") closeDetail();
    else if (key === "k") document.getElementById("previousAlertButton").click();
    else if (key === "j") document.getElementById("nextAlertButton").click();
    else return;
    event.preventDefault();
    return;
  }
  if (currentView !== "triage") return;
  if (key === "j" && focusedIndex < currentVerdicts.length - 1) {
    focusAlert(focusedIndex + 1);
  } else if (key === "k" && focusedIndex > 0) {
    focusAlert(focusedIndex - 1);
  } else if (key === "enter") {
    openDetail(currentVerdicts[focusedIndex]);
  } else if (key === "a") {
    const verdict = currentVerdicts[focusedIndex];
    if (verdict && !verdict.human_verdict && mode !== "demo") feedback(verdict.id, verdict.verdict);
  } else if (key === "d") {
    // Open the alert and land the caret in the review note. The queue cards
    // carry no inline correction panel, so review happens on the detail page.
    const verdict = currentVerdicts[focusedIndex];
    if (verdict && !verdict.human_verdict && mode !== "demo") {
      openDetailById(Number(verdict.id), { focusNotes: true });
    }
  } else if (key === "u") {
    const verdict = currentVerdicts[focusedIndex];
    if (verdict && !verdict.human_verdict && mode !== "demo") feedback(verdict.id, null, "uncertain");
  } else {
    return;
  }
  document.querySelector(`[data-idx="${focusedIndex}"]`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  event.preventDefault();
});

initializeView();
hydrateFilterStateFromUrl();
canonicalizeTriageUrl();
syncQueueLinks();
// The first call is the page's initial load and must render the detail view.
// Every later call is a scheduled tick and must leave it untouched.
let initialLoadComplete = false;
startIndependentPolling({
  loadMain: () => {
    const refreshDetail = !initialLoadComplete;
    initialLoadComplete = true;
    return load({ refreshDetail });
  },
  loadSpc,
});
