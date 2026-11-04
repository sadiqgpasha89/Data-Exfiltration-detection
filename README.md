# Sentinel Data Exfiltration Detection & Prevention

A tri-layered system for detecting and stopping data exfiltration at a financial institution: a wire-speed rules layer at the edge, an anomaly-detection layer, and an investigation layer that reasons over identity, HR and change-management context and hands a human a signed case file.

The design targets a hybrid deployment (on-premises OpenStack edge, Google Cloud enclave). **This repository is a working reference implementation of that design, not a deployed product.** The platform integrations (Kafka, Redis, BigQuery, Vertex AI, Neutron, the identity provider, Vault) are in-process stand-ins behind small interfaces; the detection logic, the decision policy, the security controls and the tests are real. [What is simulated](#what-is-and-is-not-real) is listed in full below.

## Architecture

```
 Telemetry (endpoints, databases, NetFlow)
        │  POST /api/v1/evaluate/process   (API key, validated body, load shedding)
        ▼
 ┌─ EDGE (on-premises) ─────────────────────────────────────────────────────────────┐
 │  Validation → tokenization (HMAC pseudonyms, masked hosts, sanitized SQL)         │
 │  Layer 1 rules: exact-data match · Luhn/IBAN/SSN · C2 IP/domain feeds ·            │
 │                 honeytokens · entropy and chi-square tests                        │
 └─────────────────────────────────┬─────────────────────────────────────────────────┘
                                   ▼
 ┌─ ANALYTICS ───────────────────────────────────────────────────────────────────────┐
 │  Feature store: true 15m / 1h / 24h windows + 180-day read-to-export counters     │
 │  Layer 2: Isolation Forest · PCA autoencoder · IAM entitlement scorer → score S    │
 └─────────────────────────────────┬─────────────────────────────────────────────────┘
                                   │  S ≥ 0.65, or a Layer 1 flag
                                   ▼
 ┌─ INVESTIGATION ───────────────────────────────────────────────────────────────────┐
 │  Triage · Correlation (IAM, HR, change tickets) · Compliance agents               │
 │  Decision policy (evidence only) → verdict, severity, playbook                    │
 │  Guarded containment: dry run by default · protected targets · hourly cap         │
 └─────────────────────────────────┬─────────────────────────────────────────────────┘
                                   ▼
        Hash-chained audit ledger (durable) ─► SOC cockpit ─► analyst closes the case
```

### Layer 1: deterministic rules (target: under 1 ms)

* Exact Data Match: file hashes of proprietary assets through a Bloom filter, then an exact set check.
* Luhn-validated card numbers, IBAN mod-97, plausible SSNs (areas 000, 666 and 9xx, group 00 and serial 0000 are rejected).
* Threat-intelligence feeds: exact addresses and CIDR blocks (IPv4 and IPv6) and C2 domains, matched on whole DNS labels.
* Zero-tolerance egress ports from database subnets.
* Honeytokens (canary records): one shared registry, so a canary is detected in queries and payloads, with or without separators, and every trip is recorded.
* Entropy and a chi-square test of the byte histogram against uniform (a statistic near 255 means "random-looking"; natural data is far above it).

### Layer 2: anomaly detection

* Isolation Forest over eight behavioural features, calibrated so that its score is 0.5 at the edge of the benign training data.
* A PCA bottleneck autoencoder (linear, NumPy) whose reconstruction error is calibrated against its own training distribution.
* An IAM entitlement scorer: shortest-path distance from the user to the resource in the IAM graph, plus resignation and privileged-hop signals.
* The ensemble weights the three (0.35 / 0.35 / 0.30) and escalates when any single model is above 0.85.

Neither the autoencoder nor the entitlement scorer is a neural network, and the registry says so.

### Layer 3: investigation and decision

Three deterministic agents gather evidence (process and payload forensics, identity/HR/ticket context, regulatory exposure) and the orchestrator applies a decision policy to the evidence. There is no language model in this layer.

| Verdict | When |
|---|---|
| `LEGITIMATE_BULK_OPERATION` | A change ticket is valid **for this user, at the time of the event, for this data and this destination**, and there is no hard indicator, no departing employee, no sensitive-data or concealment finding and no extreme score |
| `MALICIOUS_EXFILTRATION` | A hard indicator (honeytoken, known C2, proprietary-file match), or a score of 0.85 or more, or a departing employee with a score of 0.70 or more, or an unauthorized bulk transfer with a score of 0.70 or more and two corroborating signals |
| `SUSPICIOUS_ANOMALY_PENDING_HITL` | Score of 0.65 or more, or a sensitive-data finding, or a ticket that exists but cannot be trusted alone |
| `FALSE_POSITIVE` | Everything else that reached Layer 3 |

The `category` field of a telemetry event is a label chosen by whoever sent it. It is displayed and never used to make a decision.

## Security model

| Control | What it does |
|---|---|
| Authentication | Every API route needs an API key (`X-API-Key` or `Authorization: Bearer`). Keys are compared as SHA-256 digests in constant time. |
| Roles | `viewer` (read), `ingest` (send telemetry), `analyst` (read, ingest, close cases, contain), `admin` (everything, including retraining and the simulator). |
| Identity | The analyst in the audit ledger is the authenticated caller. A name in a request body is ignored. |
| Containment | Automatic containment is `dry_run` by default. It never touches protected users or addresses, and is capped per hour. Targets come from the case, not the request. Statuses are honest: `APPLIED`, `DRY_RUN`, `SIMULATED`, `FAILED`. |
| Tokenization | HMAC-SHA256 pseudonyms with an operator-supplied key. Production refuses to start without a real key. |
| Input | Every telemetry field is bounded and validated (ports, sizes, addresses, timestamps, identifiers). Request bodies are capped; scanning of payloads is bounded. |
| Abuse limits | Per-key token-bucket rate limit (429) and a concurrency limit (503 with `Retry-After`). |
| Audit | Append-only hash chain, written durably when `LEDGER_PATH` is set, verified at start-up (a tampered file stops the service), with a `/readyz` check. |
| Browser | The cockpit escapes all API data before rendering it, and sets CSP, frame and content-type headers. |
| Start-up gate | With `APP_ENV=production` the service refuses to start unless a tokenization key, API keys and a ledger path are set and authentication is on. |

## Running it

Development (authentication off, simulator on):

```bash
make install
make run            # http://127.0.0.1:8080
```

Production-shaped (authentication on, durable ledger, read-only container):

```bash
make keys           # prints a tokenization key and an admin API key; put them in .env
cp .env.example .env   # then edit
docker compose --env-file .env up --build
```

The cockpit asks for an API key the first time a call returns 401 and keeps it for that browser tab only.

### Operating notes

* `GET /healthz` is liveness. `GET /readyz` is readiness (ledger intact, IAM directory and threat intelligence loaded) and returns 503 with the failing checks.
* **Run one worker per ledger.** The case queue, the feature windows, the rate limiter and the ledger file are per process.
* The hash chain makes tampering detectable, not impossible: anyone who can rewrite the whole file can rewrite the whole chain. Copy the head hash (`/api/v1/incidents/worm/verify`) somewhere the host operator cannot write.
* Reference data (IAM directory, tickets, threat intelligence) is read from `data/`. The files shipped there are synthetic samples; point the `*_PATH` settings at your own.

### API

| Route | Role |
|---|---|
| `POST /api/v1/evaluate/process` | ingest |
| `POST /api/v1/telemetry/ingest`, `GET /api/v1/telemetry/recent` | ingest, viewer |
| `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}`, `GET /api/v1/incidents/worm/verify` | viewer |
| `POST /api/v1/incidents/{id}/adjudicate` | analyst |
| `POST /api/v1/remediation/execute-playbook` (body: `case_id`) | analyst (protected targets: admin) |
| `GET /api/v1/incidents/overrides/flagged` | admin |
| `GET /api/v1/metrics`, `GET /api/v1/drift/report` | viewer |
| `POST /api/v1/drift/trigger-retrain` | admin |
| `POST /api/v1/simulator/inject/{scenario}`, `POST /api/v1/telemetry/inject-seed` | admin, development only |

## Measured quality

Model quality is no longer asserted: `make benchmark` generates a labelled set of benign and malicious telemetry (including awkward benign cases: night batch jobs and large compressed downloads), runs it through the real rules, feature store and models, and computes the metrics. The latest run, on 720 events of which 120 are malicious:

| Metric | Result |
|---|---|
| Ensemble PR-AUC / ROC-AUC | 0.879 / 0.983 |
| Precision and recall at τ = 0.65 | 0.816 and 0.925 |
| False-positive rate at τ = 0.65 (and at 95% recall) | 4.2% |
| Dispatch to Layer 3: recall / false-dispatch rate | 100% / 6.0% |
| Alert volume not sent to Layer 3 | 78.3% |
| PR-AUC by model: Isolation Forest / autoencoder / entitlement | 0.780 / 0.933 / 0.994 |

**Read these with care.** The data is synthetic and was written by the authors of the detector, so the numbers are optimistic and say nothing about real traffic. The entitlement scorer's near-perfect score mostly reflects that the benchmark's attacker personas carry the signals it looks for. The benchmark is a regression gate (`tests/evaluation`) and a way to find blind spots, not a production claim.

The design document's targets (false-positive rate below 0.001 at 95% recall, 85% alert reduction, 80% transit saving) are **not met** by this build and are no longer reported as met. The dashboard shows what was measured, and `n/a` where nothing has been.

## Tests

```bash
make test          # 180 tests, ~10 s, 95% line coverage
make test-eval     # the benchmark regression gate
make lint
make audit         # dependency vulnerabilities
```

## What is and is not real

**Real and tested:** validation, tokenization, every Layer 1 rule, the feature windows, the three Layer 2 models and their calibration, the ticket authorization logic, the decision policy, the containment guard, case closure rules, the durable hash-chained ledger, authentication, authorization, rate limiting and load shedding, the drift statistics (PSI, Wasserstein, KS) on the live feature stream, and the benchmark.

**Stand-ins:** Kafka, Redis, BigQuery and Vertex AI are in-process and bounded. The containment adapters (Neutron, identity provider, Vault) report `SIMULATED` until real ones are registered with `register_backend()`. Retraining is recorded as `REQUESTED_NO_BACKEND_CONFIGURED` until a backend is registered, and is an administrator's decision on purpose. Change-ticket signatures are not verified. The three agents are deterministic and the prompt registry is not wired to a model.

**Limits to know about:** the models are fitted on a synthetic benign baseline (`fit()` on real benign telemetry before relying on the scores); steganography cannot be detected reliably from file bytes alone, so a random-looking large image is flagged for inspection, not condemned; the cockpit's Content-Security-Policy still allows inline scripts because the markup uses inline handlers.

## Changelog

**1.1.0** fixes and hardening, in short: every endpoint is authenticated and role-checked; the verdict no longer trusts a sender-controlled field; change tickets are checked for validity window, scope and self-approval; domain matching is on whole labels; the steganography test reads chi-square in the right direction; the feature store uses true time windows and bounded memory; the autoencoder no longer saturates on one flag and no longer discards the sign of its latent code; metrics are measured instead of padded; containment is guarded and honest; the audit ledger is durable, tamper-checked on start-up and thread-safe; the cockpit escapes all data and contains the case it shows instead of a hard-coded host; the tokenization key is no longer a published default.
