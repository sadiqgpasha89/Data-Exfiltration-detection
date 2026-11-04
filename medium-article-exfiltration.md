# I Audited My Own Data-Exfiltration Detector and Found 18 Ways It Would Fail a Real Bank

### A three-layer detection system looked impressive on its dashboard. When I tested it, the dashboard was partly made up, the API had no locks, and a single field in a telemetry event could decide a verdict. Here is what I found, how I fixed it, and what the system measurably does now.

Most of an insider-threat system's value comes down to one moment. A database administrator pulls 480,000 customer records at 11:45 on a Sunday night. Within seconds the platform has to decide whether that is a scheduled migration or the start of a breach, and then decide whether to cut the DBA off the network.

I built **Sentinel**, a tri-layered exfiltration detection and prevention system for a financial institution. It has a wire-speed rules layer, an anomaly-detection layer with three models, and an investigation layer that checks IAM, HR and change-ticket context before writing a signed incident dossier. It had a polished cockpit, a five-tier metrics dashboard and 51 passing tests.

Then I went through the code the way an attacker, an auditor and a skeptical SRE would. This article is the account of that review. It covers the architecture, the 18 defects I found (each one reproduced before I touched it), what I changed, what the system measurably does now, and what is still simulated.

The code is on GitHub: **github.com/sadiqgpasha89/Data-Exfiltration-detection**

---

## How Sentinel works

```
 Telemetry (endpoints, databases, NetFlow)
        │  POST /api/v1/evaluate/process
        ▼
 ┌─ EDGE ───────────────────────────────────────────────────────────────┐
 │ Validate → tokenize (HMAC pseudonyms, masked hosts, sanitized SQL)   │
 │ Layer 1 rules: exact match · Luhn/IBAN/SSN · C2 feeds · honeytokens  │
 │                · entropy and chi-square tests                        │
 └───────────────────────────────┬──────────────────────────────────────┘
                                 ▼
 ┌─ ANALYTICS ──────────────────────────────────────────────────────────┐
 │ Feature store: true 15m / 1h / 24h windows + drip counters           │
 │ Layer 2: Isolation Forest · PCA autoencoder · IAM entitlement scorer │
 └───────────────────────────────┬──────────────────────────────────────┘
                                 │ score ≥ 0.65, or a Layer 1 flag
                                 ▼
 ┌─ INVESTIGATION ──────────────────────────────────────────────────────┐
 │ Triage · Correlation (IAM, HR, tickets) · Compliance agents          │
 │ Decision policy (evidence only) → verdict and playbook               │
 │ Guarded containment: dry run by default                              │
 └───────────────────────────────┬──────────────────────────────────────┘
                                 ▼
     Hash-chained ledger ─► SOC cockpit ─► an analyst closes the case
```

**Layer 1** is deterministic and cheap. It matches file hashes of proprietary assets through a Bloom filter, validates card numbers with the Luhn checksum, IBANs with mod-97 and SSNs for plausibility, and checks destinations against threat-intelligence feeds. It also trips on **honeytokens** (canary records that no legitimate process should ever read) and tests payloads for high entropy and for byte distributions that look random.

**Layer 2** scores everything Layer 1 lets through. An Isolation Forest finds multidimensional outliers. An autoencoder flags behavior unlike the benign baseline. A graph scorer measures how far a user's access path is from what the IAM directory entitles them to, plus signals like a pending resignation. The three scores are blended into one number between 0 and 1.

**Layer 3** investigates anything with a score of 0.65 or more, or any Layer 1 flag. Three agents gather evidence: forensics on the process and payload, identity and HR context including change tickets, and regulatory exposure. A decision policy turns the evidence into a verdict, and a signed dossier goes to a human.

The ideas are sound. The implementation had problems at every layer.

---

## The audit: 18 defects

I wrote a probe for each suspicion before changing any code, and most items below are something I watched fail. A few (the unscoped-ticket path, the hard-coded user, the Makefile path) are plain to see in the code and I did not need a probe.

### A. Security defects

**1. The API had no authentication.** Not weak authentication: none. In my test, an anonymous `POST /remediation/execute-playbook` returned 200, as did `POST /drift/trigger-retrain` and `GET /incidents/worm/verify`. Anyone who could reach the port could trigger containment, read every incident and start a retraining job.

**2. A field the sender controls decided the verdict.** The orchestrator's escalation rule included `event.category == "insider_collusion"`. The `category` field is a free-text label in the telemetry itself. I posted the same 20 MB export from an ordinary retail user twice, changing only that label. With `category: "routine"` the verdict was `SUSPICIOUS_ANOMALY_PENDING_HITL` with a risk of 0.75. With `category: "insider_collusion"` it became `MALICIOUS_EXFILTRATION`, risk 0.88, **auto-mitigated**: in a real deployment, the host quarantined and the user's sessions revoked (in this build the containment backend is simulated). Anyone who can post an event could choose to knock a colleague offline.

**3. Change tickets authorized more than they should.** A valid ticket turns a scary bulk export into a dismissed false positive, so ticket matching is the most valuable thing an attacker can abuse. The matching code had three holes:
- It never checked `valid_from` or `valid_until`. The ticket's validity window was ignored.
- It matched destinations with `destination_ip in subnet` on strings, so `192.0.2.10` was "inside" the approved subnet `192.0.2.100/32`.
- A ticket that listed no tables and no subnets approved everything its requester did.

**4. The tokenization key was published in the repository.** The default `TOKENIZATION_KEY_HEX` was a 64-character counting sequence in `config.py`. Identifiers were hashed as `sha256(key:value)`, a construction that is not a proper keyed MAC, and internal host addresses used MD5.

**5. The audit ledger could be written to by the caller.** Analyst closures took `analyst_id` from the request body, so a rogue analyst could file the closure under a colleague's name. The anti-collusion audit record did not store the analyst at all. The ledger was in memory only, not thread-safe despite being appended to from a thread pool, and `verify` raised an unhandled exception (HTTP 500) on a broken chain instead of reporting it.

**6. The cockpit had stored XSS.** Telemetry fields such as process names, queries and domains end up in dossiers, and the cockpit rendered them with `innerHTML` and no escaping. I posted an event whose process name was `<img src=x onerror=window.__pwned=1>.exe`. With the original renderer, `window.__pwned` became `true` in the analyst's browser. In a SOC tool, that is the page a defender is staring at when an attacker's data arrives.

**7. One-click containment hit a hard-coded target.** The quarantine button for every incident called `execute1ClickIsolation(caseId, '10.240.12.84', 'usr_dev_4091')`. Whichever case an analyst clicked, the same host and user were contained. The success message ("Okta session terminated…") also appeared whatever the server returned.

**8. There was no input validation.** A destination port of 99999 and negative byte counts were accepted and processed.

### B. Detection defects

**9. Domain matching was substring matching.** `is_malicious_domain` tested `bad in domain`. It flagged `not-pastebin-anonymizer.community` and `dns-tunnel-relay.xyz.example.org`, which is a domain belonging to someone else that merely contains the listed name.

**10. The steganography test read the chi-square statistic in the wrong direction.** For 256 byte values, a uniformly random stream gives a statistic of about 255. Natural data (text, bitmaps) is far from uniform and gives a statistic in the thousands or millions. The code flagged media files with `chi_square > 200`, which is the structured side. A plain English text file named `photo.png` was flagged, with a statistic of 3.8 million.

**11. SSN validation accepted numbers that are never issued.** Areas 000, 666 and 900-999, group 00 and serial 0000 all passed.

**12. The "sliding windows" were not windows.** `connection_frequency_15m` was the length of the user's whole stored history, and `destination_cardinality_1h` counted unique destinations over all of it. In my probe, four events three days apart produced a 15-minute connection count of 4 and an hourly destination count of 4. Memory was also unbounded: the feature cache and the per-user state were never evicted.

**13. A user name was hard-coded into a feature.** The "privileged role hop" flag was set when `event.user_id == "usr_dev_4091"` and the query mentioned cardholders. That worked for the demo and for nobody else.

**14. The autoencoder saturated on a single flag.** Its standardization divided by `std + 1e-4`. The privileged-hop feature is always zero in the benign baseline, so one `1` became a z-score of about 10,000 and pushed the score to 1.0 regardless of everything else. Separately, the encoder applied a ReLU, which discards the sign of every latent coordinate. On benign data the mean reconstruction error was 0.73 with the ReLU and 0.54 as a plain PCA reconstruction.

### C. Honesty defects

**15. The dashboard reported numbers the system had not measured.** On a freshly started system with zero traffic, the business metrics said 124 alerts processed, 110 autonomous resolutions, 14 escalations and $2.5 million in loss avoided (floors written as `max(124, actual)`). The fatigue metric was clamped to at least 85%. Throughput had a floor of 1,250 events per second. The "bandwidth saved" figure was clamped to at least 80%. When I made it a real measurement, it was 2.8%: the tokenized record is only slightly smaller than the original.

**16. Model quality was typed in.** The false-positive rate was `min(0.0007, calculated)`, so the dashboard's "target met" was always true. The model registry claimed a PyTorch variational autoencoder and a graph neural network at 0.95 to 0.97 PR-AUC, none of which existed. The drift report, when given no data, drew a random "healthy production" sample from NumPy. Retraining returned `DISPATCHED_TO_VERTEX_PIPELINES` every time. Containment returned `APPLIED_SUCCESS` every time.

### D. Engineering defects

**17. The repo could not run from a clone.** `.gitignore` excluded the `data/` directory, which holds the IAM directory, tickets and threat-intel feeds the code loads. Four unrelated models also called `np.random.seed(42)` at import time, resetting the process-wide random stream.

**18. The build assumed one laptop.** The Makefile contained an absolute path to `/home/sgp-z/.local/bin/uv`. There was no Dockerfile, no CI, no readiness check and a `/healthz` that returned the literal strings "ONLINE", "CONNECTED" and "SYNCED" without checking anything.

---

## The fixes

### Make the boundary real

**Authentication and roles.** Every API route now requires an API key (`X-API-Key` or a bearer token). Keys are configured as `name:role:key`, held only as SHA-256 digests and compared in constant time. Four roles split the work: `viewer` reads, `ingest` sends telemetry, `analyst` closes cases and contains, and `admin` does everything including retraining. A key must be at least 16 characters, and a malformed `API_KEYS` setting fails closed with a 503 instead of leaving the door open.

**The actor comes from the key.** The analyst recorded in the audit ledger is the authenticated caller. A `analyst_id` in the request body is ignored, and my test sends a fake one to prove it.

**Validation.** The telemetry model is the trust boundary, so every field is bounded: ports from 0 to 65535, non-negative sizes, entropy from 0 to 8, valid IPv4 and IPv6 addresses, ISO timestamps, a SHA-256 pattern for hashes and length caps on every string. Bad input gets a 422. Request bodies are capped, and payload scanning is bounded so a hostile payload cannot become a denial of service.

**A start-up gate.** With `APP_ENV=production`, the service refuses to start unless a real tokenization key and API keys are set, authentication is on and a ledger path is configured. It also rejects the old published key by name. The problem list is logged in full, so an operator sees every missing piece at once.

**Abuse limits.** A per-key token-bucket rate limit returns 429 with `Retry-After`. A concurrency limit returns 503 with `Retry-After` when pipeline slots are exhausted, which is real backpressure: the old "backpressure ratio" measured how full a buffer was that nothing ever drained.

### Tokenization done properly

Identifiers become HMAC-SHA256 pseudonyms keyed by an operator-supplied secret, with the identifier type mixed in so two kinds of identifier can never collide. Internal hosts keep their network prefix and get a keyed host token, so subnet topology survives. In development, an unset key produces an ephemeral random key and a warning, never a shared default.

Two details came out of testing. First, the "is this address internal?" check used Python's `is_private`, which also covers documentation ranges like `203.0.113.0/24`. That is not the organization's own network, and masking it would have destroyed the external addresses the threat-intel layer matches on. I replaced it with an explicit RFC 1918 and unique-local check. Second, the SQL sanitizer now removes quoted literals (including doubled-quote escapes), Luhn-valid card numbers, SSNs, emails and numbers after comparison operators, while leaving non-card 16-digit numbers alone.

### Fix the detectors

- **Domains** match on whole DNS labels: the listed domain itself or a subdomain of it, case-insensitively, ignoring a trailing dot. The IP feed also accepts CIDR blocks and IPv6.
- **Chi-square** is read the right way round. A statistic's p-value against 255 degrees of freedom says whether the bytes are consistent with uniformly random, which is the condition worth flagging in a large media file. Structured files are no longer condemned.
- **SSNs** are checked for plausibility.
- **Honeytokens** now have one registry. Before, the canary value was hard-coded in the tokenizer and in the Layer 1 engine, and the "vault" module that managed canaries was wired to nothing. The shared registry matches queries and payloads, with or without spaces and dashes, records every trip, and never returns canary values in listings.
- **Feature windows** are real. Counts over 15 minutes and unique destinations over one hour are computed from event timestamps, history is trimmed to 24 hours, users are evicted least-recently-used, the cache is a fixed-size LRU, and the whole thing is guarded for concurrent access.
- **The privileged hop** now comes from the IAM graph: access to a resource the user holds no grant on, or a staging tool such as `7z.exe` running off hours. A quant reading cardholder data is flagged because the directory says they have no grant, and the DBA who has the grant is not.
- **Models** are fitted on one shared benign baseline with local random generators. The autoencoder is a linear PCA bottleneck, calibrated in log space against its own training errors, with floored standard deviations and clipped z-scores. The Isolation Forest is calibrated so that 0.5 sits at the edge of benign data. The graph scorer separates "unmanaged identity" (suspicious) from "ordinary external destination" (weak evidence).

On the seed events, the benign teller query went from an ensemble score of 0.25 to 0.05, while the attack events scored between 0.70 and 0.86. The one exception is the honeytoken query, which scores low on the models and is caught by Layer 1 instead, which is the point of a canary.

### Decide on evidence, not on labels

The verdict is now a policy over evidence the system can check:

- A **hard indicator** (a honeytoken, a known C2 destination or a proprietary-file match) is malicious.
- A **score of 0.85 or more** is malicious.
- A **departing employee with a score of 0.70 or more** is malicious.
- An **unauthorized bulk transfer** (100,000 or more records, or 1 GB or more) with a score of 0.70 or more and at least two corroborating signals is malicious.
- A **valid ticket** dismisses activity only if there is no hard indicator, no departing employee, no sensitive-data or concealment finding and no extreme score. A ticket explains bulk activity. It never launders a C2 destination or a card number found in the payload.
- Anything else at or above 0.65, with sensitive data, or with a ticket that cannot be trusted alone, goes to a human.

The `category` label is displayed and ignored.

The ticket check itself now requires all of these: the ticket is approved and belongs to this user, the **event time** falls inside the validity window (evaluated against when the activity happened, not when it was investigated), it was not approved by its own requester, it limits what it covers, the data touched is one of the approved tables by whole name, and the destination is inside an approved subnet using real CIDR containment. When a ticket is rejected, the dossier says why, so an analyst sees "outside the validity window" instead of just "no ticket".

### Containment you can trust

Containment is the one action that can hurt the business, so it got the most care:

- **Modes.** `AUTO_REMEDIATION_MODE` is `off`, `dry_run` (the default, which records what would be done and changes nothing) or `enforce`.
- **Protected targets.** Executives, break-glass accounts and core infrastructure listed in `PROTECTED_USER_IDS` and `PROTECTED_IPS` are never contained automatically.
- **Blast radius.** Automatic containment is capped per hour, so a flood of crafted events cannot be turned into mass lockouts.
- **Idempotency.** A retried request does not contain twice.
- **Honest statuses.** Every action reports `APPLIED`, `DRY_RUN`, `SIMULATED`, `FAILED` or `SKIPPED`. The default backend only simulates, and reports `SIMULATED`, never `APPLIED`. A dossier is marked `AUTO_MITIGATED` only when every action was verifiably applied. Otherwise it is `CONTAINMENT_RECOMMENDED` and stays open for a human.
- **Targets come from the case.** The API takes a case ID. The host and user to contain are the ones recorded in the dossier, so a caller cannot point it at an arbitrary address. Protected targets need an administrator.

```
 request ─► already handled? ─► mode? ─► protected? ─► hourly cap? ─► run 3 actions
              │ yes: replay      │ off    │ yes: block   │ yes: block    isolate host
              ▼                  ▼ block   ▼              ▼               revoke session
          same outcome                                                    revoke leases
                                                                          ─► all APPLIED? → effective
```

### An audit trail that survives

The ledger is still a SHA-256 hash chain, but it is now thread-safe, writes each block durably (flushed and fsynced) before adding it in memory, and reloads and **verifies the whole file at start-up**. A tampered file, or a deleted block, stops the service from starting. The anti-collusion record now names the analyst. A broken chain is reported as data (`chain_valid: false` with the first bad index) instead of a 500, and `/readyz` takes the instance out of rotation when the chain fails.

A hash chain makes tampering detectable, not impossible: anyone who can rewrite the whole file can rewrite the whole chain. The honest advice, which the README gives, is to copy the head hash somewhere the host operator cannot write.

### Fix the cockpit

All API data is escaped before rendering, and I verified it the same way I found the bug. With the original script, my payload executed (`window.__pwned === true`, two injected image elements). With the new one, the same stored incident renders the markup as literal text and nothing runs. The quarantine button now sends only the case ID. The success message shows the real per-action statuses. Missing metrics show `n/a`, and the API key is requested once per browser tab and kept only for that session.

### Measure instead of assert

This was the change I was most uncomfortable to make, because the honest numbers are worse than the fake ones.

I built a **labelled benchmark**. It generates 720 events (600 benign and 120 malicious across six attack families, in time order) and runs them through the real rules, a private feature store and the real models. The benign set includes the awkward cases on purpose: night batch jobs and large compressed downloads. Metrics, the model registry and the drift baseline all read from this instead of from literals. It runs in the background after start-up, so no request waits for it.

The latest run:

```
 Ensemble PR-AUC / ROC-AUC                         0.879 / 0.983
 Precision / recall at the 0.65 threshold          0.816 / 0.925
 False-positive rate at the 0.65 threshold         4.2%
 Layer 3 dispatch: recall / false-dispatch rate    100% / 6.0%
 Alerts not sent to Layer 3                        78.3%
 PR-AUC by model: Isolation Forest / autoencoder / entitlement   0.780 / 0.933 / 0.994
```

The design document's targets were a false-positive rate below 0.001 at 95% recall, an 85% alert reduction and an 80% transit saving. **The build does not meet any of them**, and the dashboard no longer says it does. This benchmark is also optimistic: the data is synthetic and was written by the author of the detector, and the entitlement scorer's near-perfect score mostly reflects that my attacker personas carry the signals it looks for. It is a regression gate and a blind-spot finder, not a production claim.

Other metrics changed the same way. With no data, a metric is `null`. "Loss avoided" counts exposure only when containment verifiably happened. Hallucination rate and trajectory accuracy are reported as not applicable, because the agents are deterministic and no language model generates text. Drift reports `INSUFFICIENT_DATA` until it has 200 real feature vectors, then computes PSI, Wasserstein distance and KS per feature on the live stream. Retraining is recorded as `REQUESTED_NO_BACKEND_CONFIGURED` until a real backend is registered, and it is an administrator action on purpose, because a model that retrains itself on live traffic can be poisoned by the traffic it is meant to catch.

### Operations

A single-worker Docker image runs as a non-root user with a read-only filesystem and a durable ledger volume. The image's health check calls `/readyz`, which checks that the ledger chain is intact and that the IAM directory and threat intelligence loaded. CI runs the suite on Python 3.11 and 3.12 with a coverage floor, plus a dependency audit and a check that production refuses an empty configuration. `make keys` generates a tokenization key and an API key. The Makefile no longer has my home directory in it, and the sample reference data is now tracked so a fresh clone runs.

The image uses **one worker on purpose**: the case queue, feature windows, rate limiter and ledger file are per process, so several workers would each get their own copy and could interleave appends to one file.

---

## One event, step by step

Here is what happens now when a DBA's account runs a 2 GB `pg_dump` of the customer master at 23:45.

1. **Gate.** The request carries an `ingest` key. The key is checked, the rate limit applies, the body size is checked, the event is validated and a concurrency slot is taken. If the platform is saturated, the sender gets a 503 and retries.
2. **Tokenize and featurize.** The user becomes `usr_tok_…`, the host `10.240.x.…`, and the SQL has its literals replaced. The feature store computes windowed features: off hours is true, the read-to-export ratio is low, and the privileged-hop flag comes from the IAM graph.
3. **Layer 1.** No hard indicators fire, but the transfer is over 10 MB, so the action is `FLAG_DEEP_INSPECTION`.
4. **Layer 2.** The Isolation Forest, the autoencoder and the entitlement scorer produce a combined score of 0.75.
5. **Layer 3, evidence.** The correlation agent checks the IAM graph, HR and tickets against the **event time**. The only ticket for this user is valid from 02:00 to 06:00 (and covers a different table and subnet), so it is rejected, and the dossier cites the reason: the event is outside its validity window. The compliance agent maps the dump to the regulations and computes the exposure.
6. **Decision.** No hard indicator, not a departing employee, and a score below 0.85, but this is an unauthorized bulk transfer (480,000 records) with off-hours activity as a corroborating signal. The policy returns `MALICIOUS_EXFILTRATION` with a risk of at least 0.85.
7. **Containment.** The evidence does not reach the bar for automatic containment (a hard indicator or a score of 0.85), so the dossier recommends containment and waits for an analyst.
8. **Ledger.** The dossier hash is appended to the chain and written to disk.
9. **Analyst.** An analyst with an `analyst` key opens the case in the cockpit and clicks contain. The host and user come from the case, protected targets would need an admin, and the backend reports each action's real status. Closing the case writes an audit block with the analyst's authenticated name, and if they had dismissed a case with a risk of 0.85 or more, the override would be flagged to the CISO list.

---

## What I tested

The suite grew from 51 tests to 180, with 95% line coverage, and it runs in about ten seconds. Each defect above has a regression test, including the ones that are easiest to get wrong:

- **Tickets:** the window boundaries are inclusive, `192.0.2.10` is rejected against `192.0.2.100/32`, an unscoped ticket authorizes nothing, and a self-approved ticket fails.
- **Category spoofing:** the same evidence with different labels gives the same verdict, and no containment is attempted.
- **A valid ticket and a C2 destination:** the verdict is still malicious.
- **Containment:** dry run changes nothing, a failing backend shows `FAILED`, the hourly cap stops a flood and the cap recovers after an hour.
- **Ledger:** persistence across restarts, refusal to start on a tampered or truncated file, and 400 concurrent appends that keep the chain valid.
- **API:** every route is checked without a key, the role matrix is checked, `analyst_id` in the body is ignored, an oversized body is rejected with 413, the rate limit and load shedding return the right codes and headers, and unhandled errors do not leak details.
- **Benchmark:** a regression floor under the measured metrics, so a future change that makes detection worse fails CI.

---

## What is still simulated

I want to be precise here, because the first version of this project was not.

**Real and tested:** validation, tokenization, every Layer 1 rule, the feature windows, the three models and their calibration, ticket authorization, the decision policy, the containment guard, case rules, the durable ledger, authentication, rate limiting, load shedding, the drift statistics and the benchmark.

**Stand-ins:**
- Kafka, Redis, BigQuery and Vertex AI are bounded in-process stand-ins.
- The containment adapters for Neutron, the identity provider and Vault report `SIMULATED` until real ones are registered.
- Change-ticket signatures are not verified.
- The three agents are deterministic, and the prompt registry is not connected to a model.
- The models are fitted on a synthetic benign baseline, and have to be fitted on real benign telemetry before the scores mean anything.

**Not run here:** I did not build the Docker image or run the CI workflow in this environment. The test suite, the benchmark and the cockpit (in a real browser) were run.

**Honest limits:** steganography cannot be detected reliably from file bytes alone, so a random-looking large image is flagged for inspection, not condemned. The cockpit's Content-Security-Policy still allows inline scripts because the markup uses inline event handlers. And state is per process, so the design scales by sharding, not by adding workers.

---

## What I learned

1. **A dashboard is a claim.** Every number on it should be traceable to something measured, and a metric with no data should say so. The most corrosive bugs here were the floors: `max(124, actual)` is a bug that turns "no traffic" into "healthy".
2. **Never let the input describe itself.** If a field is chosen by the party you are investigating, it can inform a display and cannot decide anything.
3. **Authority needs scope, time and an independent approver.** Every hole in the ticket logic was a missing bound: a missing window, a substring instead of a network, or an empty scope that meant "everything".
4. **Dangerous actions get modes, protected lists and caps.** Dry run by default and honest statuses cost almost nothing, and they are what lets you turn automation on without fearing the first false positive.
5. **Test the direction of a statistic.** A chi-square test against the wrong tail looks plausible and flags every file with structure.
6. **Honest numbers are better than good ones.** The benchmark showed a 4.2% false-positive rate against a stated target of 0.1%. That is the number a bank would need to see to decide whether to run this, and it points directly at the next piece of work: real benign data.

Explore the code, run the benchmark and tell me what I missed: **github.com/sadiqgpasha89/Data-Exfiltration-detection**
