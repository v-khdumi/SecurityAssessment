"use strict";
const element = id => document.getElementById(id);
let ready = false;
let choice;
let pilot = false;
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
    element("review-sample").disabled = false;
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
    pilot = state.single_subscription;
    revision = state.revision;
    reviewConfigured = state.foundry_configured;
    element("pilot-scope").hidden = !pilot;
    element("azure").disabled = !state.azure_configured;
    if (!state.azure_configured) element("azure").checked = false;
    element("azure-status").textContent = state.azure_configured ? "Configured; access not tested" : "Setup required";
    element("foundry-status").textContent = reviewConfigured ? "Review agents configured · access not tested" : "Review agents · open Setup to connect";
  } catch {
    revision = null;
    reviewConfigured = false;
    element("azure").checked = false;
    element("azure").disabled = true;
    element("azure-status").textContent = "Setup check failed";
    element("foundry-status").textContent = "Setup check failed";
  }
  element("review-label").textContent = reviewConfigured ? "Review and confirm" : "Connect review agents";
}

function populateSetup(settings) {
  const foundry = settings.foundry;
  setupRevision = settings.revision;
  savedKey = foundry.has_key === true;
  element("model-key").value = "";
  element("azure-tenant").value = settings.azure_tenant;
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
  populateSetup({azure_tenant: "", foundry: {}, revision: null});
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
  const body = JSON.stringify({azure_tenant: value("azure-tenant"), foundry, revision: setupRevision});
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
    element("azure").checked = false;
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

function showLogin(reply) {
  element("login-message").textContent = `${reply.login}: ${reply.error} Confirm the assessment again after signing in.`;
  const command = element("login-command");
  command.textContent = "";
  command.hidden = true;
  element("login-show").disabled = false;
  element("login-show").onclick = () => {
    command.textContent = `az login --tenant ${reply.tenant} --allow-no-subscriptions`;
    command.hidden = false;
    element("login-show").disabled = true;
  };
  element("login").showModal();
}

element("review").addEventListener("click", () => {
  if (!ready) return;
  if (!reviewConfigured) {
    openSetup();
    return;
  }
  const archive = element("archive").files[0];
  const azure = !element("azure").disabled && element("azure").checked;
  if (!archive && !azure) {
    element("status").textContent = element("azure").disabled
      ? "Select a configuration ZIP to continue. Live Azure collection is not available in this session."
      : "Select a configuration ZIP or choose Collect current settings from Azure.";
    return;
  }
  if (archive && archive.size > 24 * 1024 * 1024) {
    element("status").textContent = "The ZIP archive exceeds 24 MiB.";
    return;
  }
  const categories = [];
  if (archive) categories.push("ZIP: recognized Entra policies, normalized inventory and RBAC, public Prowler catalogs, and normalized compliance summaries, if present. All other entries are excluded.");
  if (azure) categories.push("Live Azure: subscriptions, groups, resource types and regions, RBAC (object ID, type, role ID), App Service publishing policies, sticky setting name counts, presence of diagnostic settings, group costs, 30-day HTTP totals, and Defender and Azure Policy aggregates. No setting values, publishing credentials, alert content, or tenant writes.");
  if (azure && pilot) categories.push("Pilot scope: one subscription configured at startup. This limits live collection only and does not change the ZIP scope.");
  categories.push("Foundry receives only allowlisted Azure and Entra setting values and temporary row numbers. It determines the findings. No ZIP, resource or principal IDs, names, logs, costs, or raw metrics are sent. Calls can incur costs and produce telemetry.");
  confirmRun({archive, azure, sample: false, revision}, categories);
});

element("review-sample").addEventListener("click", () => {
  if (!ready) return;
  confirmRun({sample: true}, [
    "Offline demo: open only the built-in sample, which contains synthetic Graph policies and fictional Azure resources.",
    "Create a demo report and CSVs locally. Neither review agent is called. No Azure connection or sign-in is used."
  ]);
});

function confirmRun(settings, categories) {
  const list = element("categories");
  list.replaceChildren(...categories.map(text => {
    const li = document.createElement("li");
    li.textContent = text;
    return li;
  }));
  choice = settings;
  element("consent-title").textContent = settings.sample ? "Approve the offline demo" : "Review the data categories before running";
  element("confirm-label").textContent = settings.sample
    ? "I approve processing the synthetic example and saving a demo report in the local folder."
    : "I have read the mandate. I confirm that the local folder and the configured Foundry deployment are approved by my organization and authorize transfer of the listed configuration indicators. My archive contains only permitted configuration evidence.";
  element("start").textContent = settings.sample ? "Run offline demo" : "Start assessment";
  element("confirmed").checked = false;
  element("start").disabled = true;
  element("consent").showModal();
}

function showResult(reply, offlineDemo) {
  const notice = element("result-notice");
  notice.hidden = !reply.sample && reply.has_evidence;
  notice.textContent = reply.sample ? "Synthetic sample. These findings do not describe your tenant."
    : "No usable configuration evidence. Zero findings is not a clean bill of health.";
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
  element("result-sources").textContent = `Recognized ZIP files: ${reply.eligible_files}. Entries not opened: ${reply.skipped}. Live Azure: ${reply.live_azure ? "queried; see the report for scope" : "not queried"}.`;
  element("result-ai").textContent = offlineDemo ? "AI review was not called in the offline demo."
    : `Foundry assessed ${reply.model_evidence_rows} evidence rows; ${reply.model_insufficient} were insufficient. The model determines findings. This is not a compliance verdict.`;
  element("open-report").href = reply.preview;
  element("open-findings").href = `${reply.preview}#findings`;
  element("download").href = reply.download;
  element("result").hidden = false;
  element("report-title").focus({preventScroll: true});
  element("result").scrollIntoView();
}

function startProgress(sample, azure) {
  const steps = [["evidence", "Read configuration evidence"], ...(azure ? [["azure", "Collect live Azure settings"]] : []),
    ["posture", "AI · Security Posture"], ["compliance", "AI · Compliance"], ["report", "Build the local report"]];
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
  for (const [id] of steps) update(id, sample && ["posture", "compliance"].includes(id) ? "skipped" : "waiting",
    sample && ["posture", "compliance"].includes(id) ? "Offline demo; no Azure call." : "");
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
element("login-close").addEventListener("click", () => element("login").close());

element("start").addEventListener("click", async () => {
  if (!element("confirmed").checked || !choice) return;
  const {archive, azure, sample} = choice;
  element("consent").close();
  element("review").disabled = true;
  element("review-sample").disabled = true;
  element("open-setup").disabled = true;
  const status = element("status");
  status.textContent = sample ? "Running the offline demo..." : azure
    ? "Assessment in progress. Live Azure collection may take several minutes." : "Assessment in progress.";
  element("result").hidden = true;
  const progress = startProgress(sample, azure);
  const headers = {"X-Assessment-Consent": "configuration-only", "Content-Type": "application/zip",
    "Accept": "application/x-ndjson"};
  if (azure) headers["X-Azure-Consent"] = "readonly-config";
  if (!sample) {
    headers["X-Foundry-Consent"] = "minimized-configuration";
    headers["X-Setup-Revision"] = String(choice.revision);
  }
  try {
    const response = await fetch(sample ? "sample" : "assess", {method: "POST", headers, body: archive || new Uint8Array()});
    const {status: outcome, payload: reply} = await readRun(response, progress);
    if (outcome !== 200) {
      status.textContent = reply.error;
      progress.finish(false, reply.error);
      if (reply.login) showLogin(reply);
      if (outcome === 409 && !reply.login) await loadReadiness();
      return;
    }
    progress.finish(true);
    status.textContent = sample ? "Offline demo report created. No cloud calls were made." : "Local snapshot created.";
    showResult(reply, sample);
  } catch {
    status.textContent = "The connection closed before the assessment result arrived. Check whether the app is running and try again.";
    progress.finish(false, status.textContent);
  } finally {
    element("review").disabled = false;
    element("review-sample").disabled = false;
    element("open-setup").disabled = false;
  }
});

loadMandate();
loadReadiness();
