# Sentinel Exfiltration: diagrams (Mermaid)

Paste each block into https://mermaid.live (or any Mermaid viewer) and export PNG or SVG for Medium.

## 1. Architecture

```mermaid
flowchart TB
    SRC["Telemetry sources<br/>endpoints · databases · NetFlow"]
    CLIENT["Callers<br/>ingest · viewer · analyst · admin API keys"]

    subgraph API["API (FastAPI, one worker per ledger)"]
        direction TB
        GATE["Request gate<br/>API key + role · rate limit · body cap · validation · load shedding"]
        subgraph EDGE["Edge (on-prem)"]
            direction TB
            TOK["Tokenization<br/>HMAC pseudonyms · masked hosts · sanitized SQL"]
            L1["Layer 1 rules<br/>exact match · Luhn/IBAN/SSN · C2 feeds · honeytokens · entropy + chi-square"]
        end
        subgraph ANA["Analytics"]
            direction TB
            FS["Feature store<br/>15m / 1h / 24h windows · drip counters"]
            L2["Layer 2 models<br/>Isolation Forest · PCA autoencoder · IAM entitlement scorer"]
        end
        subgraph INV["Investigation"]
            direction TB
            AG["Agents<br/>triage · correlation · compliance"]
            POL["Decision policy<br/>evidence only"]
            GUARD["Containment guard<br/>mode · protected targets · hourly cap"]
        end
        CASE["Case manager<br/>closure rules"]
    end

    IAM[("IAM graph · HR · change tickets")]
    LED[("Hash-chained ledger<br/>durable · verified at start-up")]
    BENCH["Labelled benchmark<br/>measured model quality"]
    DRIFT["Drift monitor<br/>PSI · Wasserstein · KS"]
    COCK["SOC cockpit<br/>escaped rendering"]
    BACKEND["Containment backend<br/>Neutron · IdP · Vault (simulated by default)"]

    SRC --> CLIENT --> GATE
    GATE --> TOK --> L1
    TOK --> FS --> L2
    L1 -- "flag or hard drop" --> AG
    L2 -- "S ≥ 0.65" --> AG
    AG <--> IAM
    AG --> POL --> GUARD
    GUARD -. "enforce only" .-> BACKEND
    POL --> LED
    POL --> CASE
    CASE --> LED
    CASE --> COCK
    FS -. "live window" .-> DRIFT
    L2 -. "scores" .-> BENCH
```

## 2. One event, end to end

```mermaid
sequenceDiagram
    autonumber
    participant S as Sender
    participant G as Request gate
    participant P as Pipeline
    participant L1 as Layer 1 rules
    participant L2 as Layer 2 models
    participant A as Agents
    participant D as Decision policy
    participant R as Containment guard
    participant K as Ledger
    actor AN as Analyst

    S->>G: POST /evaluate/process (API key, body)
    G->>G: authenticate, role "ingest", rate limit, body size
    G->>G: validate event (ports, sizes, addresses, timestamp)
    G->>G: take a concurrency slot (else 503 Retry-After)
    G->>P: event
    P->>P: tokenize, extract windowed features
    P->>L1: evaluate(event)
    L1-->>P: action, triggered rules, flags
    P->>L2: score(event, features)
    L2-->>P: S from three models
    alt S below 0.65 and Layer 1 passed
        P-->>S: result, no case
    else escalated
        P->>A: investigate
        A->>A: forensics, IAM/HR/ticket check at event time, compliance exposure
        A-->>D: evidence
        D->>D: verdict from evidence (the category label is ignored)
        opt malicious with strong evidence
            D->>R: automated containment
            R->>R: mode, protected list, hourly cap, idempotency
            R-->>D: APPLIED, DRY_RUN, SIMULATED, FAILED or blocked
        end
        D->>K: append dossier hash
        D-->>S: result with dossier
    end
    AN->>G: POST /incidents/{id}/adjudicate (analyst key)
    G->>K: append audit block (analyst from key, suspicious override check)
```

## 3. Decision policy

```mermaid
flowchart TD
    START["Event reached Layer 3"] --> HONEY{"Honeytoken<br/>touched?"}
    HONEY -- yes --> MAL1["MALICIOUS · CRITICAL · risk 1.0<br/>auto-containment eligible"]
    HONEY -- no --> TK{"Valid ticket for this user,<br/>time, data and destination?"}
    TK -- yes --> CLEAN{"No hard indicator, departing employee,<br/>sensitive data or score ≥ 0.85?"}
    CLEAN -- yes --> LEGIT["LEGITIMATE_BULK_OPERATION<br/>risk ≤ 0.30 · dismissed"]
    CLEAN -- no --> HARD
    TK -- no --> HARD{"Known C2, proprietary file match,<br/>score ≥ 0.85, departing employee with S ≥ 0.70,<br/>or unauthorized bulk + 2 signals?"}
    HARD -- yes --> MAL["MALICIOUS_EXFILTRATION"]
    MAL --> AUTO{"Hard indicator or score ≥ 0.85?"}
    MAL1 --> AUTO
    AUTO -- yes --> GUARD["Containment guard<br/>off · dry run · enforce"]
    AUTO -- no --> REC["CONTAINMENT_RECOMMENDED<br/>analyst approval required"]
    GUARD -- "enforce, backend APPLIED" --> AM["AUTO_MITIGATED"]
    GUARD -- "dry run, blocked, simulated, failed" --> REC
    HARD -- no --> SUS{"Score ≥ 0.65, sensitive data,<br/>or untrusted ticket?"}
    SUS -- yes --> HITL["SUSPICIOUS · HITL_PENDING"]
    SUS -- no --> FP["FALSE_POSITIVE · dismissed"]
```

## 4. Containment guard

```mermaid
flowchart LR
    REQ["Containment requested<br/>case id, host, user"] --> SEEN{"Case already<br/>handled?"}
    SEEN -- yes --> REPLAY["Return the earlier outcome<br/>(never contain twice)"]
    SEEN -- no --> MODE{"AUTO_REMEDIATION_MODE"}
    MODE -- off --> BLOCK1["Blocked: switched off"]
    MODE -- "dry_run / enforce" --> PROT{"Protected user<br/>or address?"}
    PROT -- yes --> BLOCK2["Blocked: protected target"]
    PROT -- no --> CAP{"enforce and hourly<br/>cap reached?"}
    CAP -- yes --> BLOCK3["Blocked: blast-radius cap"]
    CAP -- no --> RUN["Run the three actions<br/>isolate host · revoke session · revoke leases"]
    RUN --> DRY{"dry_run?"}
    DRY -- yes --> DR["Each action: DRY_RUN<br/>nothing changed"]
    DRY -- no --> BE["Backend result per action<br/>APPLIED · SIMULATED · FAILED"]
    BE --> EFF{"All APPLIED?"}
    EFF -- yes --> OK["effective = true"]
    EFF -- no --> NOTOK["effective = false<br/>case stays open for a human"]
```
