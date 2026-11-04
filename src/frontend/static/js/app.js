/**
 * Sentinel Data Exfiltration Detection & Prevention - Frontend Controller
 */

// Everything that comes from the API is untrusted text: telemetry fields (process names, queries, domains) are chosen by
// whoever generated the event, and they end up in dossiers. Escape before putting any of it in HTML.
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

// "n/a" for a metric the server could not measure (null), instead of printing "null" or inventing a value.
function fmt(value, suffix = "") {
  return value === null || value === undefined ? "n/a" : `${value}${suffix}`;
}

function storedKey() {
  try { return sessionStorage.getItem("sentinel_api_key") || ""; } catch (e) { return ""; }
}

// api() with the API key. On a 401 the operator is asked for a key once; it is kept for this browser tab only.
async function api(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (storedKey()) headers["X-API-Key"] = storedKey();
  let res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    const entered = window.prompt("This API requires an API key:");
    if (entered) {
      try { sessionStorage.setItem("sentinel_api_key", entered.trim()); } catch (e) { /* storage blocked: key lasts one request */ }
      headers["X-API-Key"] = entered.trim();
      res = await fetch(url, { ...options, headers });
    }
  }
  return res;
}

async function errorText(res) {
  try { const body = await res.json(); return body.detail || res.statusText; } catch (e) { return res.statusText; }
}

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  loadTelemetry();
  loadIncidents();
  loadMetrics();
  loadGovernance();

  // Auto-refresh metrics every 15 seconds
  setInterval(loadMetrics, 15000);
});

// TAB SWITCHING
function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      const targetPane = document.getElementById(tab.dataset.tab);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// 1. TELEMETRY
async function loadTelemetry() {
  try {
    const res = await api("/api/v1/telemetry/recent?limit=25");
    if (!res.ok) return;
    const events = await res.json();
    renderTelemetryTable(events);
  } catch (err) {
    console.error("Failed to load telemetry:", err);
  }
}

function renderTelemetryTable(events) {
  const tbody = document.getElementById("telemetry-tbody");
  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="loading-cell">No telemetry events currently in buffer.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(evt => {
    const isHighEntropy = evt.payload_entropy > 7.5;
    const entropyBadge = isHighEntropy
      ? `<span class="badge badge-danger">${evt.payload_entropy.toFixed(2)}</span>`
      : `<span class="badge badge-info">${evt.payload_entropy.toFixed(2)}</span>`;

    const volumeStr = evt.bytes_out > 1000000
      ? `${(evt.bytes_out / (1024 * 1024)).toFixed(1)} MB`
      : `${evt.bytes_out.toLocaleString()} B`;

    return `
      <tr>
        <td><strong>${esc(evt.event_id)}</strong></td>
        <td>${esc(evt.timestamp.split("T")[1].replace("Z", ""))}</td>
        <td><span class="badge badge-purple">${esc(evt.event_type)}</span></td>
        <td>${esc(evt.source_ip)} <br><small class="text-muted">${esc(evt.user_id || "system")}</small></td>
        <td>${esc(evt.destination_ip)}:${esc(evt.destination_port)}</td>
        <td>${entropyBadge}</td>
        <td>${volumeStr} <br><small>${esc(evt.record_count)} recs</small></td>
        <td><span class="badge badge-warning">${esc(evt.category)}</span></td>
        <td>
          <button class="btn btn-secondary" onclick="evaluateSingleEvent('${esc(evt.event_id)}')" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;">
            ⚡ Evaluate
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

async function injectSeedStream() {
  const btn = document.getElementById("btn-inject-seed");
  const originalText = btn.innerHTML;
  btn.innerHTML = `<span>⏳</span> Ingesting...`;
  btn.disabled = true;

  try {
    const res = await api("/api/v1/telemetry/inject-seed", { method: "POST" });
    if (!res.ok) {
      alert(`Seed data unavailable: ${await errorText(res)}`);
      return;
    }
    await res.json();
    await loadTelemetry();
    await loadMetrics();
    // Switch to stream tab
    document.getElementById("tab-btn-stream").click();
  } catch (err) {
    alert("Error injecting stream: " + err.message);
  } finally {
    btn.innerHTML = originalText;
    btn.disabled = false;
  }
}

function refreshTelemetry() {
  loadTelemetry();
}

async function evaluateSingleEvent(eventId) {
  // Find event in table or fetch
  const res = await api("/api/v1/telemetry/recent?limit=100");
  const events = await res.json();
  const target = events.find(e => e.event_id === eventId);
  if (!target) return;

  const evalRes = await api("/api/v1/evaluate/process", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(target),
  });
  if (!evalRes.ok) {
    alert(`Evaluation failed: ${await errorText(evalRes)}`);
    return;
  }
  const evalData = await evalRes.json();
  
  if (evalData.incident_dossier) {
    renderSwarmDeliberation(evalData.incident_dossier);
    loadIncidents();
    document.getElementById("tab-btn-swarm").click();
  } else {
    alert(`Event ${eventId} passed Layer 1 & 2 as Benign. Score: ${evalData.layer2_evaluation.ensemble_risk_score}`);
  }
  loadMetrics();
}

// 2. INCIDENTS & HITL
async function loadIncidents() {
  try {
    const res = await api("/api/v1/incidents");
    if (!res.ok) return;
    const incidents = await res.json();
    renderIncidents(incidents);
  } catch (err) {
    console.error("Failed to load incidents:", err);
  }
}

function renderIncidents(incidents) {
  const container = document.getElementById("cases-container");
  const isOpen = i => ["HITL_PENDING", "CONTAINMENT_RECOMMENDED"].includes(i.remediation_status);
  const pendingCount = incidents.filter(isOpen).length;
  document.getElementById("pending-cases-badge").innerText = `Pending HITL: ${pendingCount}`;

  if (!incidents || incidents.length === 0) {
    container.innerHTML = `<div class="empty-state">No active incidents awaiting review. Trigger an attack simulation or evaluate an event.</div>`;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    let sevClass = "low";
    if (inc.severity === "CRITICAL") sevClass = "critical";
    else if (inc.severity === "HIGH") sevClass = "high";

    const isPending = isOpen(inc);

    return `
      <div class="case-card ${sevClass}">
        <div>
          <div class="case-card-header">
            <h3>${esc(inc.case_id)}</h3>
            <span class="badge badge-${inc.severity === 'CRITICAL' ? 'danger' : inc.severity === 'HIGH' ? 'warning' : 'success'}">${esc(inc.severity)}</span>
          </div>
          <div class="case-meta">
            Event: ${esc(inc.event_id)} &bull; Risk Score: ${(inc.final_risk_score * 100).toFixed(1)}% &bull; Status: ${esc(inc.remediation_status)}
          </div>
          <div class="case-analysis">
            <strong>Verdict:</strong> ${esc(inc.verdict)} <br>
            <strong>Root Cause:</strong> ${esc(inc.root_cause_analysis)} <br>
            <strong>Capital Exposure:</strong> $${Number(inc.estimated_capital_risk_usd).toLocaleString()}<br>
            <strong>Containment:</strong> ${esc(describeContainment(inc))}
          </div>
          <div class="case-citations">
            📜 Citations: ${esc(inc.citations.slice(0, 2).join(" | "))}
          </div>
        </div>

        <div class="case-actions">
          <button class="btn btn-secondary" onclick="viewDossierModal('${esc(inc.case_id)}')">
            🔍 View Full Dossier
          </button>
          ${isPending ? `
            <button class="btn btn-danger" onclick="execute1ClickIsolation('${esc(inc.case_id)}')">
              🛑 Contain host and user
            </button>
            <button class="btn btn-success" onclick="adjudicateCase('${esc(inc.case_id)}', 'DISMISSED_BENIGN')">
              ✅ Dismiss as Benign
            </button>
          ` : `
            <span class="badge badge-info">Resolved (${esc(inc.remediation_status)})</span>
          `}
        </div>
      </div>
    `;
  }).join("");
}

function describeContainment(inc) {
  const c = inc.containment || {};
  if (inc.remediation_status === "AUTO_MITIGATED") return "applied automatically";
  if (c.blocked_reason) return `not applied: ${c.blocked_reason}`;
  if (c.mode === "dry_run" && c.executed) return "dry run: recorded, nothing was changed";
  return inc.verdict === "MALICIOUS_EXFILTRATION" ? "recommended, awaiting analyst approval" : "none";
}

async function adjudicateCase(caseId, action) {
  const res = await api(`/api/v1/incidents/${encodeURIComponent(caseId)}/adjudicate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: action, notes: "Adjudicated via Cyber SOC Cockpit interface" }),
  });
  if (!res.ok) {
    alert(`Could not close the case: ${await errorText(res)}`);
    return;
  }
  const data = await res.json();
  if (data.audit_check && data.audit_check.is_suspicious_override) {
    alert("⚠️ ANTI-COLLUSION AUDIT TRIGGERED: Contradiction between Agent Critical Risk and Human Dismissal has been escalated to CISO!");
  }
  loadIncidents();
  loadMetrics();
}

async function execute1ClickIsolation(caseId) {
  const res = await api("/api/v1/remediation/execute-playbook", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: caseId }),
  });
  if (!res.ok) {
    alert(`Containment was not executed: ${await errorText(res)}`);
    return;
  }
  const data = await res.json();
  const lines = data.executed_actions.map(a => `${a.action}: ${a.status}`).join("\n");
  alert(`${data.effective ? "Containment applied" : "Containment NOT verifiably applied"} for ${data.target.user_id} @ ${data.target.ip}\n\n${lines}`);
  loadIncidents();
  loadMetrics();
}

// 3. SWARM DELIBERATION
function renderSwarmDeliberation(dossier) {
  document.getElementById("active-swarm-case").innerText = `Case: ${esc(dossier.case_id)} (${esc(dossier.verdict)})`;

  const feed = document.getElementById("debate-feed");
  if (!dossier.debate_turns || dossier.debate_turns.length === 0) {
    feed.innerHTML = `<div class="debate-placeholder">No debate turns recorded.</div>`;
    return;
  }

  feed.innerHTML = dossier.debate_turns.map(turn => `
    <div class="debate-turn-card">
      <div class="debate-turn-header">
        <span class="debate-agent-name">${esc(turn.agent_name)}</span>
        <span class="debate-confidence">Confidence: ${(turn.confidence * 100).toFixed(0)}%</span>
      </div>
      <div class="debate-rationale">
        <strong>Hypothesis:</strong> ${esc(turn.hypothesis)} <br>
        <strong>Finding:</strong> ${esc(turn.rationale)} <br>
        <strong>Proposed Action:</strong> <span class="badge badge-info">${esc(turn.proposed_action)}</span>
      </div>
      <div class="debate-citations">
        ${turn.supporting_citations.map(c => `<div>&bull; ${esc(c)}</div>`).join("")}
      </div>
    </div>
  `).join("") + `
    <div style="margin-top: 1rem; padding: 1rem; background: rgba(6, 182, 212, 0.05); border: 1px solid var(--color-cyan); border-radius: var(--radius-sm);">
      <h4 style="color: var(--color-cyan); margin-bottom: 0.5rem;">Cryptographic WORM SHA-256 Ledger Anchor:</h4>
      <div class="worm-hash-pill">${esc(dossier.worm_immutable_hash)}</div>
    </div>
  `;
}

// 4. METRICS OBSERVATORY
async function loadMetrics() {
  try {
    const res = await api("/api/v1/metrics");
    if (!res.ok) return;
    const report = await res.json();
    
    // Business
    const b = report.business_metrics;
    document.getElementById("kpi-loss-avoided").innerText = `$${Number(b.total_capital_loss_avoided_usd || 0).toLocaleString()}`;
    document.getElementById("kpi-mttd").innerText = `${fmt(b.mttd_minutes)} min (target <2.0m)`;
    document.getElementById("kpi-mttr").innerText = `${fmt(b.mttr_minutes)} min (target <5.0m)`;
    document.getElementById("kpi-fatigue").innerText = `${fmt(b.soc_analyst_fatigue_reduction_pct, "%")} (target >=85%)`;

    // System
    const s = report.system_metrics;
    document.getElementById("kpi-p99-latency").innerText = `${fmt(s.p99_latency_ms)} ms`;
    document.getElementById("kpi-l1-latency").innerText = `${fmt(s.l1_rule_evaluation_p99_ms)} ms`;
    document.getElementById("kpi-l2-latency").innerText = `${fmt(s.l2_ml_inference_p99_ms)} ms`;
    document.getElementById("kpi-edge-savings").innerText = fmt(s.hybrid_transit_cost_savings_pct, "%");
    document.getElementById("transit-savings-badge").innerText = `Record size saved: ${fmt(s.hybrid_transit_cost_savings_pct, "%")}`;
    document.getElementById("live-eps-badge").innerText = `EPS: ${Number(s.ingestion_throughput_eps || 0).toLocaleString()} events/s`;

    // ML (from the labelled benchmark)
    const m = report.ml_metrics;
    document.getElementById("kpi-pr-auc").innerText = m.measured ? m.pr_auc : `n/a (${m.status || "not measured"})`;
    document.getElementById("kpi-fpr").innerText = m.measured ? `${m.false_positive_rate_at_95_tpr} (target <0.001)` : "n/a";
    document.getElementById("kpi-brier").innerText = fmt(m.brier_calibration_score);
    document.getElementById("kpi-f1").innerText = fmt(m.f1_score);

    // Retrieval (no generated text, so no faithfulness score)
    const r = report.rag_metrics;
    document.getElementById("kpi-rag-score").innerText = fmt(r.ticket_match_rate);
    document.getElementById("kpi-rag-recall").innerText = fmt(r.context_retrievals);
    document.getElementById("kpi-rag-precision").innerText = fmt(r.retrievals_with_valid_ticket);
    document.getElementById("kpi-rag-faith").innerText = "n/a";

    // Agentic
    const a = report.agentic_metrics;
    document.getElementById("kpi-task-comp").innerText = fmt(a.task_completion_rate_pct, "%");
    document.getElementById("kpi-traj-acc").innerText = "n/a";
    document.getElementById("kpi-hallucination").innerText = "n/a";
    document.getElementById("kpi-consensus-cycles").innerText = fmt(a.average_consensus_convergence_cycles);

  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

// 5. GOVERNANCE & DRIFT
async function loadGovernance() {
  try {
    const res = await api("/api/v1/drift/report");
    if (!res.ok) return;
    const gov = await res.json();

    // Drift
    const d = gov.drift_metrics;
    document.getElementById("psi-value").innerText = d.status === "INSUFFICIENT_DATA" ? `collecting data (${d.samples}/${d.samples_needed})` : fmt(d.psi_score);
    document.getElementById("wasserstein-value").innerText = fmt(d.wasserstein_distance);
    document.getElementById("ks-stat-value").innerText = d.ks_statistic === null ? "n/a" : `${d.ks_statistic} (p=${d.ks_p_value})`;

    // Models
    const tbody = document.getElementById("model-registry-tbody");
    tbody.innerHTML = gov.production_models.map(m => `
      <tr>
        <td><strong>${esc(m.model_id)}</strong></td>
        <td>${esc(m.algorithm)}</td>
        <td>${esc(m.version)}</td>
        <td>${esc(fmt(m.pr_auc))}</td>
        <td><span class="badge badge-success">${esc(m.status)}</span></td>
      </tr>
    `).join("");

    // Prompts
    const promptCont = document.getElementById("prompt-templates-container");
    promptCont.innerHTML = gov.prompt_templates.map(p => `
      <div class="prompt-card">
        <h4>${esc(p.agent_name)} (${esc(p.version)})</h4>
        <div class="prompt-snippet">"${esc(p.system_prompt.slice(0, 110))}..."</div>
        <div class="prompt-hash">SHA-256: ${esc(p.sha256_checksum.slice(0, 20))}...</div>
      </div>
    `).join("");

  } catch (err) {
    console.error("Failed to load governance:", err);
  }
}

async function triggerRetraining() {
  const res = await api("/api/v1/drift/trigger-retrain", { method: "POST" });
  if (!res.ok) {
    alert(`Retraining was not requested: ${await errorText(res)}`);
    return;
  }
  const data = await res.json();
  alert(`Retraining request recorded. Status: ${data.status}`);
  loadGovernance();
}

// 6. SIMULATOR
async function injectSimulation(scenarioName) {
  try {
    const res = await api(`/api/v1/simulator/inject/${encodeURIComponent(scenarioName)}`, { method: "POST" });
    if (!res.ok) {
      alert(`Simulation unavailable: ${await errorText(res)}`);
      return;
    }
    const data = await res.json();
    
    renderSwarmDeliberation(data.incident_dossier);
    await loadTelemetry();
    await loadIncidents();
    await loadMetrics();

    // Auto-switch to swarm tab to show reasoning
    document.getElementById("tab-btn-swarm").click();
  } catch (err) {
    alert("Error executing attack simulation: " + err.message);
  }
}

// MODAL
async function viewDossierModal(caseId) {
  const res = await api(`/api/v1/incidents/${caseId}`);
  if (!res.ok) return;
  const dossier = await res.json();

  document.getElementById("modal-title").innerText = `Incident Dossier: ${esc(dossier.case_id)}`;
  const body = document.getElementById("modal-body");

  body.innerHTML = `
    <div class="dossier-section">
      <h4>Verdict & Threat Assessment</h4>
      <p><strong>Verdict:</strong> <span class="badge badge-${dossier.severity === 'CRITICAL' ? 'danger' : 'warning'}">${esc(dossier.verdict)}</span></p>
      <p><strong>Severity:</strong> ${esc(dossier.severity)} &bull; <strong>Final Risk Score:</strong> ${(dossier.final_risk_score * 100).toFixed(1)}%</p>
      <p><strong>Root Cause Analysis:</strong> ${esc(dossier.root_cause_analysis)}</p>
    </div>

    <div class="dossier-section">
      <h4>Regulatory Liability & Capital Exposure</h4>
      <p><strong>Applicable Frameworks:</strong> ${esc(dossier.regulatory_exposure.join(", ") || "Internal Policy")}</p>
      <p><strong>Potential Statutory Fine:</strong> $${dossier.estimated_capital_risk_usd.toLocaleString()}</p>
    </div>

    <div class="dossier-section">
      <h4>Supporting Evidence & Citations</h4>
      <ul>
        ${dossier.citations.map(c => `<li>${esc(c)}</li>`).join("")}
      </ul>
    </div>

    <div class="dossier-section">
      <h4>Remediation Playbook</h4>
      <ol>
        ${dossier.remediation_playbook.map(p => `<li>${esc(p)}</li>`).join("")}
      </ol>
    </div>

    <div class="dossier-section">
      <h4>Cryptographic WORM SHA-256 Ledger Anchor</h4>
      <div class="worm-hash-pill">${esc(dossier.worm_immutable_hash)}</div>
    </div>
  `;

  document.getElementById("incident-modal").style.display = "flex";
}

function closeModal() {
  document.getElementById("incident-modal").style.display = "none";
}
