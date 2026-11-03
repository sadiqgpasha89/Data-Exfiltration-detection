/**
 * Sentinel Data Exfiltration Detection & Prevention - Frontend Controller
 */

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
    const res = await fetch("/api/v1/telemetry/recent?limit=25");
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
        <td><strong>${evt.event_id}</strong></td>
        <td>${evt.timestamp.split("T")[1].replace("Z", "")}</td>
        <td><span class="badge badge-purple">${evt.event_type}</span></td>
        <td>${evt.source_ip} <br><small class="text-muted">${evt.user_id || "system"}</small></td>
        <td>${evt.destination_ip}:${evt.destination_port}</td>
        <td>${entropyBadge}</td>
        <td>${volumeStr} <br><small>${evt.record_count} recs</small></td>
        <td><span class="badge badge-warning">${evt.category}</span></td>
        <td>
          <button class="btn btn-secondary" onclick="evaluateSingleEvent('${evt.event_id}')" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;">
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
    const res = await fetch("/api/v1/telemetry/inject-seed", { method: "POST" });
    const data = await res.json();
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
  const res = await fetch("/api/v1/telemetry/recent?limit=100");
  const events = await res.json();
  const target = events.find(e => e.event_id === eventId);
  if (!target) return;

  const evalRes = await fetch("/api/v1/evaluate/process", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(target),
  });
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
    const res = await fetch("/api/v1/incidents");
    if (!res.ok) return;
    const incidents = await res.json();
    renderIncidents(incidents);
  } catch (err) {
    console.error("Failed to load incidents:", err);
  }
}

function renderIncidents(incidents) {
  const container = document.getElementById("cases-container");
  const pendingCount = incidents.filter(i => i.remediation_status === "HITL_PENDING").length;
  document.getElementById("pending-cases-badge").innerText = `Pending HITL: ${pendingCount}`;

  if (!incidents || incidents.length === 0) {
    container.innerHTML = `<div class="empty-state">No active incidents awaiting review. Trigger an attack simulation or evaluate an event.</div>`;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    let sevClass = "low";
    if (inc.severity === "CRITICAL") sevClass = "critical";
    else if (inc.severity === "HIGH") sevClass = "high";

    const isPending = inc.remediation_status === "HITL_PENDING";

    return `
      <div class="case-card ${sevClass}">
        <div>
          <div class="case-card-header">
            <h3>${inc.case_id}</h3>
            <span class="badge badge-${inc.severity === 'CRITICAL' ? 'danger' : inc.severity === 'HIGH' ? 'warning' : 'success'}">${inc.severity}</span>
          </div>
          <div class="case-meta">
            Event: ${inc.event_id} &bull; Risk Score: ${(inc.final_risk_score * 100).toFixed(1)}% &bull; Status: ${inc.remediation_status}
          </div>
          <div class="case-analysis">
            <strong>Verdict:</strong> ${inc.verdict} <br>
            <strong>Root Cause:</strong> ${inc.root_cause_analysis} <br>
            <strong>Capital Exposure:</strong> $${inc.estimated_capital_risk_usd.toLocaleString()}
          </div>
          <div class="case-citations">
            📜 Citations: ${inc.citations.slice(0, 2).join(" | ")}
          </div>
        </div>

        <div class="case-actions">
          <button class="btn btn-secondary" onclick="viewDossierModal('${inc.case_id}')">
            🔍 View Full Dossier
          </button>
          ${isPending ? `
            <button class="btn btn-danger" onclick="execute1ClickIsolation('${inc.case_id}', '10.240.12.84', 'usr_dev_4091')">
              🛑 1-Click Quarantine (Neutron)
            </button>
            <button class="btn btn-success" onclick="adjudicateCase('${inc.case_id}', 'DISMISSED_BENIGN')">
              ✅ Dismiss as Benign
            </button>
          ` : `
            <span class="badge badge-info">Resolved (${inc.remediation_status})</span>
          `}
        </div>
      </div>
    `;
  }).join("");
}

async function adjudicateCase(caseId, action) {
  const res = await fetch(`/api/v1/incidents/${caseId}/adjudicate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      analyst_id: "soc_tier2_analyst",
      action: action,
      notes: "Adjudicated via Cyber SOC Cockpit interface",
    }),
  });
  const data = await res.json();
  if (data.audit_check && data.audit_check.is_suspicious_override) {
    alert("⚠️ ANTI-COLLUSION AUDIT TRIGGERED: Contradiction between Agent Critical Risk and Human Dismissal has been escalated to CISO!");
  }
  loadIncidents();
  loadMetrics();
}

async function execute1ClickIsolation(caseId, ip, userId) {
  const res = await fetch("/api/v1/remediation/execute-playbook", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      case_id: caseId,
      analyst_id: "soc_lead_analyst",
      ip_address: ip,
      user_id: userId,
    }),
  });
  const data = await res.json();
  alert(`✅ Containment Executed: OpenStack Neutron port severed, Okta session terminated for ${userId}`);
  loadIncidents();
  loadMetrics();
}

// 3. SWARM DELIBERATION
function renderSwarmDeliberation(dossier) {
  document.getElementById("active-swarm-case").innerText = `Case: ${dossier.case_id} (${dossier.verdict})`;

  const feed = document.getElementById("debate-feed");
  if (!dossier.debate_turns || dossier.debate_turns.length === 0) {
    feed.innerHTML = `<div class="debate-placeholder">No debate turns recorded.</div>`;
    return;
  }

  feed.innerHTML = dossier.debate_turns.map(turn => `
    <div class="debate-turn-card">
      <div class="debate-turn-header">
        <span class="debate-agent-name">${turn.agent_name}</span>
        <span class="debate-confidence">Confidence: ${(turn.confidence * 100).toFixed(0)}%</span>
      </div>
      <div class="debate-rationale">
        <strong>Hypothesis:</strong> ${turn.hypothesis} <br>
        <strong>Finding:</strong> ${turn.rationale} <br>
        <strong>Proposed Action:</strong> <span class="badge badge-info">${turn.proposed_action}</span>
      </div>
      <div class="debate-citations">
        ${turn.supporting_citations.map(c => `<div>&bull; ${c}</div>`).join("")}
      </div>
    </div>
  `).join("") + `
    <div style="margin-top: 1rem; padding: 1rem; background: rgba(6, 182, 212, 0.05); border: 1px solid var(--color-cyan); border-radius: var(--radius-sm);">
      <h4 style="color: var(--color-cyan); margin-bottom: 0.5rem;">Cryptographic WORM SHA-256 Ledger Anchor:</h4>
      <div class="worm-hash-pill">${dossier.worm_immutable_hash}</div>
    </div>
  `;
}

// 4. METRICS OBSERVATORY
async function loadMetrics() {
  try {
    const res = await fetch("/api/v1/metrics");
    if (!res.ok) return;
    const report = await res.json();
    
    // Business
    const b = report.business_metrics;
    document.getElementById("kpi-loss-avoided").innerText = `$${b.total_capital_loss_avoided_usd.toLocaleString()}`;
    document.getElementById("kpi-mttd").innerText = `${b.mttd_minutes} min (<2.0m)`;
    document.getElementById("kpi-mttr").innerText = `${b.mttr_minutes} min (<5.0m)`;
    document.getElementById("kpi-fatigue").innerText = `${b.soc_analyst_fatigue_reduction_pct}% (>=85%)`;

    // System
    const s = report.system_metrics;
    document.getElementById("kpi-p99-latency").innerText = `${s.p99_latency_ms} ms`;
    document.getElementById("kpi-l1-latency").innerText = `${s.l1_rule_evaluation_p99_ms} ms`;
    document.getElementById("kpi-l2-latency").innerText = `${s.l2_ml_inference_p99_ms} ms`;
    document.getElementById("kpi-edge-savings").innerText = `${s.hybrid_transit_cost_savings_pct}%`;
    document.getElementById("transit-savings-badge").innerText = `Bandwidth Saved: ${s.hybrid_transit_cost_savings_pct}%`;
    document.getElementById("live-eps-badge").innerText = `EPS: ${s.ingestion_throughput_eps.toLocaleString()} events/s`;

    // ML
    const m = report.ml_metrics;
    document.getElementById("kpi-pr-auc").innerText = m.pr_auc;
    document.getElementById("kpi-fpr").innerText = `${m.false_positive_rate_at_95_tpr} (<0.001)`;
    document.getElementById("kpi-brier").innerText = m.brier_calibration_score;
    document.getElementById("kpi-f1").innerText = m.f1_score;

    // RAG
    const r = report.rag_metrics;
    document.getElementById("kpi-rag-score").innerText = r.rag_composite_score;
    document.getElementById("kpi-rag-recall").innerText = r.context_retrieval_recall;
    document.getElementById("kpi-rag-precision").innerText = r.context_precision;
    document.getElementById("kpi-rag-faith").innerText = r.faithfulness;

    // Agentic
    const a = report.agentic_metrics;
    document.getElementById("kpi-task-comp").innerText = `${a.task_completion_rate_pct}%`;
    document.getElementById("kpi-traj-acc").innerText = a.tool_trajectory_accuracy;
    document.getElementById("kpi-hallucination").innerText = a.hallucination_error_rate;
    document.getElementById("kpi-consensus-cycles").innerText = a.average_consensus_convergence_cycles;

  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

// 5. GOVERNANCE & DRIFT
async function loadGovernance() {
  try {
    const res = await fetch("/api/v1/drift/report");
    if (!res.ok) return;
    const gov = await res.json();

    // Drift
    const d = gov.drift_metrics;
    document.getElementById("psi-value").innerText = d.psi_score;
    document.getElementById("wasserstein-value").innerText = d.wasserstein_distance;
    document.getElementById("ks-stat-value").innerText = `${d.ks_statistic} (p=${d.ks_p_value})`;

    // Models
    const tbody = document.getElementById("model-registry-tbody");
    tbody.innerHTML = gov.production_models.map(m => `
      <tr>
        <td><strong>${m.model_id}</strong></td>
        <td>${m.algorithm}</td>
        <td>${m.version}</td>
        <td>${m.pr_auc}</td>
        <td><span class="badge badge-success">${m.status}</span></td>
      </tr>
    `).join("");

    // Prompts
    const promptCont = document.getElementById("prompt-templates-container");
    promptCont.innerHTML = gov.prompt_templates.map(p => `
      <div class="prompt-card">
        <h4>${p.agent_name} (${p.version})</h4>
        <div class="prompt-snippet">"${p.system_prompt.slice(0, 110)}..."</div>
        <div class="prompt-hash">SHA-256: ${p.sha256_checksum.slice(0, 20)}...</div>
      </div>
    `).join("");

  } catch (err) {
    console.error("Failed to load governance:", err);
  }
}

async function triggerRetraining() {
  const res = await fetch("/api/v1/drift/trigger-retrain", { method: "POST" });
  const data = await res.json();
  alert(`🚀 Retraining Pipeline Dispatched to Vertex AI: ${data.pipeline_name}`);
  loadGovernance();
}

// 6. SIMULATOR
async function injectSimulation(scenarioName) {
  try {
    const res = await fetch(`/api/v1/simulator/inject/${scenarioName}`, { method: "POST" });
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
  const res = await fetch(`/api/v1/incidents/${caseId}`);
  if (!res.ok) return;
  const dossier = await res.json();

  document.getElementById("modal-title").innerText = `Incident Dossier: ${dossier.case_id}`;
  const body = document.getElementById("modal-body");

  body.innerHTML = `
    <div class="dossier-section">
      <h4>Verdict & Threat Assessment</h4>
      <p><strong>Verdict:</strong> <span class="badge badge-${dossier.severity === 'CRITICAL' ? 'danger' : 'warning'}">${dossier.verdict}</span></p>
      <p><strong>Severity:</strong> ${dossier.severity} &bull; <strong>Final Risk Score:</strong> ${(dossier.final_risk_score * 100).toFixed(1)}%</p>
      <p><strong>Root Cause Analysis:</strong> ${dossier.root_cause_analysis}</p>
    </div>

    <div class="dossier-section">
      <h4>Regulatory Liability & Capital Exposure</h4>
      <p><strong>Applicable Frameworks:</strong> ${dossier.regulatory_exposure.join(", ") || "Internal Policy"}</p>
      <p><strong>Potential Statutory Fine:</strong> $${dossier.estimated_capital_risk_usd.toLocaleString()}</p>
    </div>

    <div class="dossier-section">
      <h4>Supporting Evidence & Citations</h4>
      <ul>
        ${dossier.citations.map(c => `<li>${c}</li>`).join("")}
      </ul>
    </div>

    <div class="dossier-section">
      <h4>Remediation Playbook</h4>
      <ol>
        ${dossier.remediation_playbook.map(p => `<li>${p}</li>`).join("")}
      </ol>
    </div>

    <div class="dossier-section">
      <h4>Cryptographic WORM SHA-256 Ledger Anchor</h4>
      <div class="worm-hash-pill">${dossier.worm_immutable_hash}</div>
    </div>
  `;

  document.getElementById("incident-modal").style.display = "flex";
}

function closeModal() {
  document.getElementById("incident-modal").style.display = "none";
}
