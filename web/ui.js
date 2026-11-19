"use strict";
const element = id => document.getElementById(id);
let ready = false;
let choice;
let maxZipBytes = null;
let revision = null;
let reviewConfigured = false;
let setupRevision = null;
let savedKey = false;
let saving = false;

async function loadMandate() {
  try {
    const response = await fetch("mandate.txt", {cache: "no-store"});
    if (!response.ok) throw new Error();
    element("mandate").textContent = await response.text();
    element("review").disabled = false;
    ready = true;
  } catch {
    element("mandate").textContent = "The mandate is unavailable. The assessment cannot start.";
  }
}

async function loadReadiness() {
  try {
    const response = await fetch("readiness", {cache: "no-store"});
    if (!response.ok) throw new Error();
    const state = await response.json();
    maxZipBytes = state.max_zip_bytes;
    revision = state.revision;
    reviewConfigured = state.foundry_configured;
    element("archive-limit").textContent = `(up to ${maxZipBytes / (1024 * 1024)} MiB)`;
    element("foundry-status").textContent = reviewConfigured ? "Review agents configured · access not tested" : "Review agents · open Setup to connect";
  } catch {
    revision = null;
    reviewConfigured = false;
    element("foundry-status").textContent = "Setup check failed";
  }
  element("review-label").textContent = reviewConfigured ? "Review and confirm" : "Connect review agents";
}

function populateSetup(settings) {
  const foundry = settings.foundry;
  setupRevision = settings.revision;
  savedKey = foundry.has_key === true;
  element("model-key").value = "";
  element("model-endpoint").value = foundry.endpoint || "";
  element("model-deployment").value = foundry.deployment || "";
  element("model-key").required = !savedKey;
  element("key-help").textContent = savedKey
    ? "Key already held in memory. Leave blank to keep it for the same endpoint."
    : "Kept only in this app's memory. Never written to disk or included in a report.";
}

async function openSetup() {
  const dialog = element("setup-dialog");
  setupRevision = null;
  element("setup-error").textContent = "";
  element("save-setup").disabled = true;
  populateSetup({foundry: {}, revision: null});
  dialog.showModal();
  try {
    const response = await fetch("setup", {cache: "no-store"});
    if (!response.ok) throw new Error();
    const settings = await response.json();
    if (!dialog.open) return;
    populateSetup(settings);
    element("save-setup").disabled = false;
  } catch {
    element("setup-error").textContent = "Could not load setup from the local server. If this tab is from a previous launch, reopen the workspace using the link shown at startup.";
  }
}
element("open-setup").addEventListener("click", openSetup);

for (const id of ["close-setup", "cancel-setup"]) {
  element(id).addEventListener("click", () => element("setup-dialog").close());
}
element("setup-dialog").addEventListener("cancel", event => {
  if (saving) event.preventDefault();
});
element("setup-dialog").addEventListener("close", () => { element("model-key").value = ""; });
element("setup-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (setupRevision === null || saving) return;
  const value = id => element(id).value.trim();
  const foundry = {endpoint: value("model-endpoint"), deployment: value("model-deployment"), api_key: value("model-key")};
  const body = JSON.stringify({foundry, revision: setupRevision});
  const error = element("setup-error");
  error.textContent = "";
  saving = true;
  for (const id of ["save-setup", "close-setup", "cancel-setup"]) element(id).disabled = true;
  try {
    const response = await fetch("setup", {method: "POST", cache: "no-store",
      headers: {"Content-Type": "application/json", "X-Assessment-Setup": "session-only"}, body});
    const reply = await response.json();
    if (!response.ok) {
      error.textContent = reply.error;
      return;
    }
    element("setup-dialog").close();
    await loadReadiness();
    element("status").textContent = "Setup saved for this session. No cloud connection was made.";
  } catch {
    error.textContent = "Could not save setup. Check that the local app is still running.";
  } finally {
    saving = false;
    for (const id of ["save-setup", "close-setup", "cancel-setup"]) element(id).disabled = false;
  }
});

element("review").addEventListener("click", () => {
  if (!ready) return;
  if (!reviewConfigured) {
    openSetup();
    return;
  }
  const archive = element("archive").files[0];
  if (!archive || archive.size === 0) {
    element("status").textContent = "Select a nonempty configuration ZIP to continue.";
    return;
  }
  if (maxZipBytes !== null && archive.size > maxZipBytes) {
    element("status").textContent = `The ZIP exceeds ${maxZipBytes / (1024 * 1024)} MiB. Split your configuration export by subscription or workload.`;
    return;
  }
  const categories = [];
  categories.push("Only your uploaded ZIP is used. It is streamed to a temporary file in the approved folder on the assessment host and closed after parsing. Only recognized configuration files are opened.");
  categories.push("Foundry receives only allowlisted Azure and Entra setting values and temporary row numbers. It determines the findings. No ZIP, resource or principal IDs, names, logs, costs, or raw metrics are sent. Calls can incur costs and produce telemetry.");
  confirmRun({archive, revision}, categories);
});

function confirmRun(settings, categories) {
  const list = element("categories");
  list.replaceChildren(...categories.map(text => {
    const li = document.createElement("li");
    li.textContent = text;
    return li;
  }));
  choice = settings;
  element("confirmed").checked = false;
  element("start").disabled = true;
  element("consent").showModal();
}

function showResult(reply) {
  const notice = element("result-notice");
  notice.hidden = reply.has_evidence;
  notice.textContent = "No usable configuration evidence. Zero findings is not a clean bill of health.";
  element("metric-high").textContent = reply.high;
  element("metric-findings").textContent = reply.findings;
  element("metric-resources").textContent = reply.resources;
  element("metric-graph").textContent = reply.graph_observations;
  element("priorities").replaceChildren(...reply.priority.map(item => {
    const row = document.createElement("li");
    const tier = document.createElement("span");
    tier.className = `risk-label ${item.severity.toLowerCase()}`;
    tier.textContent = item.severity;
    const title = document.createElement("strong");
    title.textContent = item.title;
    const details = document.createElement("p");
    details.textContent = `Affected: ${item.affected}. ${item.action}`;
    row.append(tier, title, details);
    return row;
  }));
  element("no-priority").hidden = reply.priority.length > 0;
  element("result-coverage").textContent = `${reply.controls_with_evidence} of ${reply.available_controls} resource controls had configuration evidence. This is coverage, not a pass rate. Graph observations are separate policy settings.`;
  element("result-sources").textContent = `Recognized ZIP files: ${reply.eligible_files}. Entries not opened: ${reply.skipped}.`;
  element("result-ai").textContent = `Foundry returned ${reply.foundry_requests} responses for ${reply.model_patterns} distinct configuration patterns, covering ${reply.model_evidence_rows} evidence rows. ${reply.model_insufficient} rows had insufficient evidence. See Method and limits for request receipts.`;
  element("open-report").href = reply.preview;
  element("open-findings").href = `${reply.preview}#findings`;
  element("download").href = reply.download;
  element("result").hidden = false;
  element("report-title").focus({preventScroll: true});
  element("result").scrollIntoView();
}

function startProgress() {
  const steps = [["upload", "Receive ZIP on the assessment host"], ["evidence", "Read configuration evidence"],
    ["posture", "AI · Security Posture"], ["compliance", "AI · Compliance"], ["report", "Build the report on the assessment host"]];
  const entries = new Map(steps.map(([id, label]) => {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    const badge = document.createElement("span");
    const detail = document.createElement("p");
    title.textContent = label;
    badge.className = "source-status";
    item.append(title, badge, detail);
    return [id, {item, badge, detail}];
  }));
  const labels = {waiting: "Queued", running: "In progress", done: "Complete", failed: "Failed", skipped: "Not called", stopped: "Stopped"};
  const update = (id, state, detail = "") => {
    const target = entries.get(id);
    if (!target || !Object.hasOwn(labels, state)) return;
    target.item.dataset.state = state;
    target.badge.textContent = labels[state];
    target.detail.textContent = detail;
  };
  element("progress-steps").replaceChildren(...Array.from(entries.values(), ({item}) => item));
  for (const [id] of steps) update(id, id === "upload" ? "running" : "waiting");
  const start = Date.now();
  const tick = () => { element("run-time").textContent = `${Math.floor((Date.now() - start) / 1000)} s elapsed`; };
  const timer = setInterval(tick, 1000);
  tick();
  element("progress").hidden = false;
  element("progress").scrollIntoView();
  return {
    update,
    finish(ok, message) {
      clearInterval(timer);
      tick();
      if (!ok) {
        const active = steps.find(([id]) => entries.get(id).item.dataset.state === "running");
        if (active) update(active[0], "failed", message);
        for (const [id] of steps) {
          if (["waiting", "running"].includes(entries.get(id).item.dataset.state)) update(id, "stopped");
        }
      }
    }
  };
}

async function readRun(response, progress) {
  if (!response.headers.get("Content-Type")?.startsWith("application/x-ndjson")) {
    return {status: response.status, payload: await response.json()};
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  let result;
  while (true) {
    const {value, done} = await reader.read();
    pending += decoder.decode(value, {stream: !done});
    const lines = pending.split("\n");
    pending = lines.pop();
    for (const line of lines) {
      if (!line) continue;
      const event = JSON.parse(line);
      if (event.event === "progress") progress.update(event.stage, event.state, event.detail);
      if (event.event === "result") result = event;
    }
    if (done) break;
  }
  if (!result) throw new Error("Missing assessment result");
  return result;
}

element("confirmed").addEventListener("change", () => {
  element("start").disabled = !element("confirmed").checked;
});
element("cancel").addEventListener("click", () => element("consent").close());

element("start").addEventListener("click", async () => {
  if (!element("confirmed").checked || !choice) return;
  const {archive, revision: approvedRevision} = choice;
  element("consent").close();
  element("review").disabled = true;
  element("open-setup").disabled = true;
  const status = element("status");
  status.textContent = "Uploading ZIP and running the assessment…";
  element("result").hidden = true;
  const progress = startProgress();
  const headers = {"X-Assessment-Consent": "configuration-only", "Content-Type": "application/zip",
    "Accept": "application/x-ndjson", "X-Foundry-Consent": "minimized-configuration",
    "X-Setup-Revision": String(approvedRevision)};
  try {
    const response = await fetch("assess", {method: "POST", headers, body: archive});
    const {status: outcome, payload: reply} = await readRun(response, progress);
    if (outcome !== 200) {
      status.textContent = reply.error;
      progress.finish(false, reply.error);
      if (outcome === 409) await loadReadiness();
      return;
    }
    progress.finish(true);
    status.textContent = "Local snapshot created.";
    showResult(reply);
  } catch {
    status.textContent = "The connection closed before the assessment result arrived. Check whether the app is running and try again.";
    progress.finish(false, status.textContent);
  } finally {
    element("review").disabled = false;
    element("open-setup").disabled = false;
  }
});

loadMandate();
loadReadiness();
