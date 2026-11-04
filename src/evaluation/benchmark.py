"""Labelled synthetic benchmark for the detection stack.

The dashboard used to show model quality from hard-coded numbers. This module measures it: it generates a labelled set
of benign and malicious telemetry, runs every event through the real Layer 1 rules, the real feature store and the real
Layer 2 models, and computes the standard metrics from the scores that come out.

Read the numbers with the right caution. The data is synthetic and was written by the same people who wrote the detector,
so the results are optimistic and say nothing about a bank's real traffic. The benchmark is a regression check (does a
change make the stack better or worse on the same set?) and a tool for finding blind spots, not a production claim. The
benign set deliberately includes the awkward cases: off-hours batch jobs and large compressed downloads.

Run it with `make benchmark`.
"""

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, precision_recall_fscore_support, roc_auc_score, roc_curve

from src.core.config import settings
from src.core.models import TelemetryEvent

BASE_DAY = datetime(2026, 9, 14, tzinfo=timezone.utc)  # a Monday
DB_USERS = {
    "usr_retail_5512": ("10.240.35.12", ["branch_teller_portal"]),
    "usr_dba_1022": ("10.240.5.10", ["customer_accounts_master", "core_ledger"]),
    "usr_analyst_3030": ("10.240.8.44", ["quarterly_regulatory_staging"]),
    "usr_soc_7821": ("10.240.20.15", ["siem_audit_logs"]),
}


def _ts(day_offset: int, hour: float) -> str:
    return (BASE_DAY + timedelta(days=day_offset, hours=hour)).isoformat()


def _event(idx: int, label: str, **kw) -> TelemetryEvent:
    base = dict(event_id=f"bench-{label}-{idx}", destination_port=5432, protocol="TCP", event_type="database_query")
    base.update(kw)
    return TelemetryEvent(**base)


def generate_dataset(n_benign: int = 600, n_per_attack: int = 20, seed: int = 7) -> List[Tuple[TelemetryEvent, int, str]]:
    """Returns [(event, label, family)] with label 1 for malicious. Deterministic for a given seed."""
    rng = np.random.default_rng(seed)
    data: List[Tuple[TelemetryEvent, int, str]] = []
    users = list(DB_USERS)

    for i in range(n_benign):
        user = users[i % len(users)]
        ip, dbs = DB_USERS[user]
        roll = rng.random()
        day = int(rng.integers(0, 5))
        if roll < 0.04:  # night batch job, internal
            ev = _event(i, "b", timestamp=_ts(day, float(rng.uniform(1, 4))), source_ip=ip, destination_ip="10.240.10.50", user_id=user,
                        process_name="etl_runner.exe", event_type="batch_export", bytes_in=int(rng.integers(500, 5000)),
                        bytes_out=int(rng.integers(1_000_000, 50_000_000)), payload_entropy=float(rng.uniform(4, 6)), record_count=int(rng.integers(1000, 20000)))
            family = "benign_night_batch"
        elif roll < 0.07:  # large compressed download from a CDN
            ev = _event(i, "b", timestamp=_ts(day, float(rng.uniform(9, 17))), source_ip=ip, destination_ip="151.101.1.69", destination_port=443,
                        user_id=user, process_name="chrome.exe", event_type="network_flow", bytes_in=int(rng.integers(5_000_000, 20_000_000)),
                        bytes_out=int(rng.integers(2000, 9000)), payload_entropy=float(rng.uniform(7.6, 7.95)))
            family = "benign_compressed_download"
        else:  # ordinary application query
            ev = _event(i, "b", timestamp=_ts(day, float(rng.uniform(8.5, 17.5))), source_ip=ip, destination_ip="10.240.10.50", user_id=user,
                        process_name="teller_portal.exe", query=f"SELECT name, balance FROM {dbs[0]} WHERE branch_id = 'B{int(rng.integers(100, 999))}' LIMIT 20",
                        bytes_in=int(rng.integers(100, 2000)), bytes_out=int(rng.integers(200, 20000)),
                        payload_entropy=float(np.clip(rng.normal(4.0, 0.7), 1, 6.5)), record_count=int(rng.integers(1, 50)))
            family = "benign_routine"
        data.append((ev, 0, family))

    n = n_per_attack
    for i in range(n):  # DNS tunnelling
        data.append((_event(i, "dns", timestamp=_ts(int(rng.integers(0, 5)), float(rng.uniform(0, 5))), source_ip="10.240.12.84", destination_ip="194.26.29.112",
                            destination_port=53, protocol="UDP", user_id="usr_dev_4091", process_name="powershell.exe", event_type="network_flow",
                            domain_queried=f"{'A' * 40}{i}.dns-tunnel-relay.xyz", bytes_in=80, bytes_out=int(rng.integers(8000, 60000)),
                            payload_entropy=float(rng.uniform(7.6, 7.99)), record_count=int(rng.integers(50, 500))), 1, "dns_tunnel"))
    for i in range(n):  # burst upload to the cloud
        data.append((_event(i, "burst", timestamp=_ts(int(rng.integers(0, 5)), float(rng.uniform(0, 24))), source_ip="10.240.5.10", destination_ip="185.220.101.5",
                            destination_port=443, user_id="usr_dba_1022", process_name="7z.exe", event_type="network_flow", bytes_in=1024,
                            bytes_out=int(rng.integers(1_000_000_000, 5_000_000_000)), payload_entropy=float(rng.uniform(7.5, 7.99)),
                            record_count=int(rng.integers(100_000, 2_000_000))), 1, "burst_cloud_upload"))
    drip_user_events = []
    for i in range(n):  # low-and-slow drip by a departing employee, in sequence so the cumulative counters move
        drip_user_events.append((_event(i, "drip", timestamp=_ts(i // 4, float(rng.uniform(21, 23.9))), source_ip="10.240.12.84", destination_ip="10.240.10.50",
                                        user_id="usr_dev_4091", process_name="python_eval.exe", event_type="batch_export",
                                        query="SELECT customer_id, ssn, balance FROM hnw_clients LIMIT 25", bytes_in=250,
                                        bytes_out=int(rng.integers(1500, 4000)), payload_entropy=float(rng.uniform(4.2, 5.0)), record_count=int(rng.integers(20, 60))), 1, "drip_exfiltration"))
    data.extend(drip_user_events)
    for i in range(n):  # concealed payload in an image
        data.append((_event(i, "stego", timestamp=_ts(int(rng.integers(0, 5)), float(rng.uniform(9, 17))), source_ip="10.240.12.84", destination_ip="203.0.113.88",
                            destination_port=443, user_id="usr_dev_4091", process_name="chrome.exe", event_type="file_egress", file_name=f"banner_{i}.png",
                            bytes_in=512, bytes_out=int(rng.integers(5_000_000, 20_000_000)), payload_entropy=float(rng.uniform(7.8, 7.99)),
                            chi_square_randomness=float(rng.uniform(235, 295)), record_count=int(rng.integers(1000, 6000))), 1, "steganography"))
    for i in range(n):  # privileged insider database dump, off hours
        data.append((_event(i, "dump", timestamp=_ts(int(rng.integers(0, 5)), float(rng.uniform(22, 23.9))), source_ip="10.240.5.10", destination_ip="10.240.10.50",
                            user_id="usr_dba_1022", process_name="pg_dump.exe", event_type="database_dump",
                            query="COPY customer_accounts_master TO STDOUT WITH (FORMAT CSV, HEADER)", bytes_in=450,
                            bytes_out=int(rng.integers(1_000_000_000, 4_000_000_000)), payload_entropy=float(rng.uniform(6.0, 7.2)),
                            record_count=int(rng.integers(200_000, 1_000_000))), 1, "insider_database_dump"))
    for i in range(n):  # a user reading data they hold no grant on
        data.append((_event(i, "unent", timestamp=_ts(int(rng.integers(0, 5)), float(rng.uniform(9, 17))), source_ip="10.240.12.84", destination_ip="10.240.10.50",
                            user_id="usr_dev_4091", process_name="dbeaver.exe", query="SELECT card_number, cvv FROM cardholder_records LIMIT 500",
                            bytes_in=300, bytes_out=int(rng.integers(20000, 90000)), payload_entropy=float(rng.uniform(4.0, 5.0)),
                            record_count=int(rng.integers(100, 500))), 1, "entitlement_abuse"))
    return data


def _metrics_at(y: np.ndarray, scores: np.ndarray) -> Dict[str, Any]:
    pred = scores >= settings.ANOMALY_DISPATCH_THRESHOLD_TAU
    p, r, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    fpr_curve, tpr_curve, _ = roc_curve(y, scores)
    ok = np.where(tpr_curve >= 0.95)[0]
    return {
        "pr_auc": round(float(average_precision_score(y, scores)), 4),
        "roc_auc": round(float(roc_auc_score(y, scores)), 4),
        "precision_at_tau": round(float(p), 4),
        "recall_at_tau": round(float(r), 4),
        "f1_at_tau": round(float(f1), 4),
        "fpr_at_tau": round(float(((pred == 1) & (y == 0)).sum() / max(1, (y == 0).sum())), 5),
        "fpr_at_95_tpr": round(float(fpr_curve[ok[0]]), 5) if len(ok) else None,
        "brier": round(float(brier_score_loss(y, np.clip(scores, 0, 1))), 5),
    }


def run_benchmark(seed: int = 7) -> Dict[str, Any]:
    # imported here: the detection stack imports the monitoring modules that import this one
    from src.data_engineering.feature_store import StreamingFeatureStore
    from src.datascience.tier1_rules import tier1_engine
    from src.datascience.tier2_ml import tier2_scorer

    dataset = generate_dataset(seed=seed)
    store = StreamingFeatureStore()  # private store: the benchmark must not touch live feature state
    y, l2_if, l2_vae, l2_graph, l2_ens, l1_flag, l2_dispatch, families = [], [], [], [], [], [], [], []
    # events are processed in time order, as a stream would deliver them
    for event, label, family in sorted(dataset, key=lambda t: t[0].timestamp):
        features = store.extract_features(event)
        l1 = tier1_engine.evaluate(event)
        l2 = tier2_scorer.evaluate(event, features)
        y.append(label)
        l2_if.append(l2.isolation_forest_score)
        l2_vae.append(l2.vae_reconstruction_loss)
        l2_graph.append(l2.graph_entitlement_deviation)
        l2_ens.append(l2.ensemble_risk_score)
        l1_flag.append(l1.action in ("HARD_DROP", "FLAG_DEEP_INSPECTION"))
        l2_dispatch.append(l2.requires_agentic_dispatch)
        families.append(family)

    y_a = np.array(y)
    dispatched = np.array(l1_flag) | np.array(l2_dispatch)
    per_family: Dict[str, Dict[str, float]] = {}
    for fam in sorted(set(families)):
        idx = np.array([f == fam for f in families])
        per_family[fam] = {"events": int(idx.sum()), "dispatch_rate": round(float(dispatched[idx].mean()), 4)}

    report = {
        "dataset": {
            "events": int(len(y_a)), "malicious": int(y_a.sum()), "benign": int((1 - y_a).sum()), "seed": seed,
            "caveat": "Synthetic, labelled by the authors of the detector. Optimistic by construction; use as a regression check, not as a production claim.",
        },
        "ensemble": _metrics_at(y_a, np.array(l2_ens)),
        "by_model": {
            "isolation_forest": {"pr_auc": round(float(average_precision_score(y_a, l2_if)), 4), "roc_auc": round(float(roc_auc_score(y_a, l2_if)), 4)},
            "autoencoder": {"pr_auc": round(float(average_precision_score(y_a, l2_vae)), 4), "roc_auc": round(float(roc_auc_score(y_a, l2_vae)), 4)},
            "graph_entitlement": {"pr_auc": round(float(average_precision_score(y_a, l2_graph)), 4), "roc_auc": round(float(roc_auc_score(y_a, l2_graph)), 4)},
        },
        "dispatch_to_layer3": {
            "recall": round(float(dispatched[y_a == 1].mean()), 4),
            "false_dispatch_rate": round(float(dispatched[y_a == 0].mean()), 4),
            "layer3_alert_reduction_pct": round(float((1 - dispatched.mean()) * 100.0), 2),
        },
        "per_family": per_family,
    }
    return report


class BenchmarkCache:
    """Runs the benchmark once, in the background, and serves the cached report.

    A run takes several seconds, so it must never block a request: `get()` returns `{"status": "computing"}` until the
    first run finishes, and `warm()` starts it.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._report: Optional[Dict[str, Any]] = None
        self._error: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self.evaluated_at: Optional[str] = None

    def _run(self) -> None:
        try:
            report = run_benchmark()
            with self._lock:
                self._report = report
                self.evaluated_at = datetime.now(timezone.utc).isoformat()
        except Exception as exc:  # reported, not raised: metrics must degrade, not take the API down
            with self._lock:
                self._error = f"{type(exc).__name__}: {exc}"

    def warm(self) -> None:
        with self._lock:
            if self._thread is None and self._report is None:
                self._thread = threading.Thread(target=self._run, name="benchmark-warmup", daemon=True)
                self._thread.start()

    def get(self) -> Dict[str, Any]:
        with self._lock:
            if self._report is not None:
                return {"status": "ready", **self._report, "evaluated_at": self.evaluated_at}
            if self._error:
                return {"status": "failed", "error": self._error}
            return {"status": "computing" if self._thread is not None else "not_started"}

    def wait(self, timeout: float = 120.0) -> Dict[str, Any]:
        """Blocks until the report is ready (used by tests and the CLI, never by request handlers)."""
        self.warm()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
        return self.get()


benchmark_cache = BenchmarkCache()


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), indent=2))
