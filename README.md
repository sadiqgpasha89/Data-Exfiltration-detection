# Sentinel Data Exfiltration Detection & Prevention System

> **Enterprise Solution Blueprint: Tri-Layered Hybrid Data Exfiltration Detection and Prevention System for Financial Institutions**

An autonomous, context-aware, low-latency, and high-throughput defense platform combining **On-Premises OpenStack** edge wire-speed processing with **Google Cloud Platform (GCP)** elastic machine learning and cognitive multi-agent reasoning.

---

## 1. Architectural Highlights

```
+---------------------------------------------------------------------------------------------------+
|                            ON-PREMISES OPENSTACK PRIVATE CLOUD EDGE                               |
|                                                                                                   |
|  [Raw Banking Telemetry] -> [Edge Ingestion & Tokenization] -> [Layer 1: High-Speed Rules]        |
|  (Endpoints, DBs, NetFlow)    (PII/PCI Masking, OCSF Format)     (EDM Bloom Filter, Luhn Regex,   |
|                                                                   C2 Blacklist, Stego Chi-Square) |
+---------------------------------------------------------------------------------------------------+
                                                  |
                          (Encrypted mTLS / Cloud Interconnect)
                          (Volume reduction > 80% to avoid transit costs)
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                 GOOGLE CLOUD PLATFORM (GCP) SECURE ENCLAVE                        |
|                                                                                                   |
|  [Streaming Feature Store]  --->  [Layer 2: Statistical & ML]  --->  [Layer 3: Agentic Swarm]     |
|  (Sliding-window stats:           (Isolation Forest, VAE              (Plan-and-Solve Swarm:      |
|   1m, 15m, 1h, 24h, 180d drip;     Reconstruction Loss, GNN            Triage, Graph-RAG Context, |
|   entropy, byte ratios)            Entitlement Deviation)              Compliance Auditor)        |
|                                                  |                              |                 |
|                                                  v                              v                 |
|  [MLOps & Governance]                     [Ensemble Score]             [Consensus & Dossier]      |
|  (PSI Drift, Wasserstein,                 (Calibrated Risk:            (WORM SHA-256 Ledger,      |
|   KS-Test, Shadow Canaries)                Threshold Tau)               1-Click / Auto Remediation)|
+---------------------------------------------------------------------------------------------------+
```

### The Tri-Layered Defense Model
1. **Layer 1 (OpenStack Edge): High-Speed Deterministic & Rule Filtering**
   - Microsecond evaluations ($< 1$ms).
   - Exact Data Match (EDM) with in-memory Bloom Filters.
   - Syntactic DFA regex engine with Luhn algorithm validation (credit cards), IBAN modulo-97, SSN checks.
   - Threat intelligence C2 IP/domain blacklists and database subnet port zero-tolerance policies.
   - Shannon Entropy payload calculation ($> 7.5$) and Chi-Square statistical randomness testing for LSB media steganography.
2. **Layer 2 (GCP Enclave): Statistical & Machine Learning Anomaly Detection**
   - Unsupervised Isolation Forest for multi-dimensional spatial NetFlow & database outliers.
   - Variational Autoencoder (VAE) reconstruction loss ($\mathcal{L} = \|x - \hat{x}\|^2$).
   - Graph Representation Learning & IAM Entitlement deviation scoring.
   - Calibrated Ensemble Scorer emitting risk score $S \in [0.0, 1.0]$ and dynamic threshold $\tau = 0.65$.
3. **Layer 3 (GCP Enclave): Cognitive Multi-Agent Reasoning Swarm with Graph-RAG**
   - Plan-and-Solve hypothesis decomposition.
   - **Triage Agent**: File headers, compression/encryption flags, and process parent-child trees.
   - **Context & Correlation Agent**: Graph-RAG queries across IAM graphs, HR resignation timelines, and Jira ITSM change orders.
   - **Policy & Compliance Auditor Agent**: Regulatory liability mapping (PCI-DSS v4.0, GDPR, GLBA, BCBS 239) and statutory fine calculation.
   - **Swarm Orchestrator**: Structured debate, reflection cycles, consensus convergence, and cryptographically signed Incident Dossier.

---

## 2. Comprehensive 5-Tier Metrics Observatory

| Metric Tier | Key Indicators | Target SLA |
| :--- | :--- | :--- |
| **1. Business & Risk** | MTTD (Mean Time to Detect) & MTTR (Mean Time to Respond) | $< 2.0$ min MTTD, $< 5.0$ min MTTR |
| | Potential Capital Loss Avoidance | Measured in USD ($) based on statutory penalty schedules |
| | SOC Analyst Fatigue Index | $\ge 85\%$ alert volume reduction via autonomous L3 resolution |
| **2. System & Wire-Speed** | End-to-End Pipeline Latency | $< 1.5$s at P99 |
| | L1 Rule Execution Latency | $< 1.0$ ms wire-speed |
| | L2 ML Inference Latency | $< 50$ ms |
| | Hybrid Transit Cost Savings | $\ge 80\%$ volume reduction at OpenStack edge |
| | Ingestion Throughput | Events Per Second (EPS) & buffer backpressure ratio |
| **3. Machine Learning** | Precision-Recall AUC (PR-AUC) | Optimized for extreme class imbalance |
| | False Positive Rate (FPR) @ 95% TPR | $< 0.001$ |
| | Brier Calibration Score | $\frac{1}{N}\sum(f_t - o_t)^2$ (Calibrated probability) |
| **4. Graph-RAG Retrieval** | Context Retrieval Recall & Context Precision | $\ge 90\%$ |
| | Faithfulness & Answer Relevancy | Strict citation grounding against ingested telemetry |
| **5. Agentic System** | Task Completion Rate | $\ge 95\%$ |
| | Tool-Use Trajectory Accuracy | Levenshtein / Graph edit distance against golden paths |
| | Hallucination / Grounding Error Rate | $< 0.1\%$ |
| | Consensus Convergence Rate | Number of deliberation cycles to consensus |

---

## 3. MLOps & LLMOps Governance

- **Continuous Drift Governance**:
  - Covariate Shift (Data Drift): Population Stability Index (PSI) & Wasserstein Distance (Earth Mover's Distance). $\text{PSI} > 0.25$ triggers automated recalibration.
  - Concept Drift: Kolmogorov-Smirnov (KS) two-sample hypothesis testing.
- **Automated Retraining Controller**: Triggers Vertex AI Pipelines (Kubeflow) on threshold breach.
- **LLMOps Prompt Registry**: Versioned prompt templates with SHA-256 checksums and schema guardrails.
- **Agent Evaluation Harness**: Benchmarking synthetic canary cases and tool sequence trajectories.
- **WORM Append-Only Ledger**: SHA-256 blockchain preventing insider collusion (e.g. DBA dumping database while rogue analyst suppresses alerts).

---

## 4. Quick Start & Testing

### Installation
```bash
# Setup virtual environment and install dependencies
/home/sgp-z/.local/bin/uv venv .venv
/home/sgp-z/.local/bin/uv pip install --python .venv/bin/python -r requirements.txt
/home/sgp-z/.local/bin/uv pip install --python .venv/bin/python -e .
```

### Run Server
```bash
.venv/bin/uvicorn src.api.main:app --host 0.0.0.0 --port 8080 --reload
```
Open your browser at `http://localhost:8080` to access the Cyber SOC Cockpit.

### Run Full Test Suite
```bash
# Run unit tests
.venv/bin/pytest tests/unit -v

# Run integration tests
.venv/bin/pytest tests/integration -v

# Run edge-case tests
.venv/bin/pytest tests/edge_case -v

# Run performance latency tests
.venv/bin/pytest tests/performance -v

# Run all tests with code coverage
.venv/bin/pytest tests -v --cov=src --cov-report=term-missing
```
