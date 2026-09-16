#!/usr/bin/env python3
"""
ScopeStorm
===============================

An engagement-ready HTTP load/resilience testing tool for AUTHORIZED
red-team and QA work only.

What makes this "red-team grade" is NOT raw firepower -- it is the
controls around the traffic:

  1. Rules of Engagement (RoE) enforcement    -- refuses to run outside a
                                                 signed, scoped config.
  2. Scope + time-window locking              -- only authorized targets,
                                                 only during allowed windows.
  3. Hash-chained audit log                   -- tamper-evident record of
                                                 every request for the report.
  4. Attributable marker headers              -- the blue team can always tell
                                                 your authorized test from a
                                                 real attack (deconfliction).
  5. Auto-abort safety thresholds             -- automatically stops if the
                                                 target starts failing, so you
                                                 MEASURE the breaking point
                                                 without actually causing an
                                                 outage.

Explicitly NOT included (by design -- these are attack techniques, not
testing techniques): IP spoofing, source obfuscation, amplification,
detection evasion, or any bypass of the hard safety caps below.

Dependencies:
    pip install requests

Run:
    python scopestorm.py --roe roe.example.json --url https://target/health
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import queue
import random
import re
import statistics
import sys
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, time as dtime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests


# ============================================================================
# HARD SAFETY LIMITS - NON-NEGOTIABLE CEILINGS
# ----------------------------------------------------------------------------
# The RoE may set LOWER values than these, never higher. These exist so the
# tool physically cannot be turned into a denial-of-service weapon.
# ============================================================================

MAX_CONCURRENCY = 25
MAX_REQUESTS_PER_SECOND = 20
MAX_DURATION_SECONDS = 300          # 5 minutes
MAX_TIMEOUT_SECONDS = 30
MAX_BODY_SIZE = 64 * 1024

DEFAULT_MARKER_HEADER = "X-Authorized-Test"

# Product identity -- defined once so the User-Agent stays in sync everywhere.
PRODUCT = "ScopeStorm"
VERSION = "1.0"


def user_agent(engagement_id: str) -> str:
    """The deconfliction User-Agent stamped on every request."""
    return f"{PRODUCT}/{VERSION} (engagement={engagement_id})"


# ============================================================================
# RULES OF ENGAGEMENT
# ============================================================================

@dataclass
class RulesOfEngagement:
    engagement_id: str
    client: str
    operator: str
    authorized_hosts: list          # exact hostnames, e.g. ["staging.acme.com"]
    # Intensity ceilings (clamped to the hard limits above)
    max_concurrency: int = 5
    max_rps: int = 5
    max_duration: int = 60
    timeout: int = 10
    # Allowed daily time window in 24h local time, inclusive start/exclusive end.
    # Use "00:00"-"23:59" to allow any time. Empty = any time.
    window_start: str = ""
    window_end: str = ""
    # Auto-abort thresholds: stop the test automatically if the target degrades.
    abort_error_rate: float = 0.25  # fraction of failed requests (0.0-1.0)
    abort_p95_latency_ms: float = 5000.0
    emergency_contact: str = ""
    # Optional pseudonym for attribution. If set, it is used everywhere the
    # operator is shown/recorded instead of the (optional) real operator, so an
    # operator can run under a handle without recording a real identity.
    operator_alias: str = ""

    @property
    def operator_label(self) -> str:
        """Alias if provided, else the real operator, else 'unspecified'.
        This is the value recorded/displayed for attribution everywhere."""
        return self.operator_alias or self.operator or "unspecified"

    @staticmethod
    def load(path: str) -> "RulesOfEngagement":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        # operator is optional (use operator_alias for a pseudonym instead)
        required = ["engagement_id", "client", "authorized_hosts"]
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise ValueError(f"RoE is missing required fields: {', '.join(missing)}")

        roe = RulesOfEngagement(
            engagement_id=str(data["engagement_id"]),
            client=str(data["client"]),
            operator=str(data.get("operator", "")),
            operator_alias=str(data.get("operator_alias", "")),
            authorized_hosts=[h.strip().lower().rstrip(".") for h in data["authorized_hosts"]],
            max_concurrency=int(data.get("max_concurrency", 5)),
            max_rps=int(data.get("max_rps", 5)),
            max_duration=int(data.get("max_duration", 60)),
            timeout=int(data.get("timeout", 10)),
            window_start=str(data.get("window_start", "")),
            window_end=str(data.get("window_end", "")),
            abort_error_rate=float(data.get("abort_error_rate", 0.25)),
            abort_p95_latency_ms=float(data.get("abort_p95_latency_ms", 5000.0)),
            emergency_contact=str(data.get("emergency_contact", "")),
        )
        roe._validate_and_clamp()
        return roe

    def _validate_and_clamp(self):
        if not self.authorized_hosts:
            raise ValueError("RoE authorized_hosts cannot be empty.")

        host_re = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
        for host in self.authorized_hosts:
            if not host_re.fullmatch(host):
                raise ValueError(f"Invalid authorized host in RoE: {host!r}")

        # Clamp intensity to the hard ceilings -- RoE can only reduce.
        self.max_concurrency = max(1, min(self.max_concurrency, MAX_CONCURRENCY))
        self.max_rps = max(1, min(self.max_rps, MAX_REQUESTS_PER_SECOND))
        self.max_duration = max(1, min(self.max_duration, MAX_DURATION_SECONDS))
        self.timeout = max(1, min(self.timeout, MAX_TIMEOUT_SECONDS))
        self.abort_error_rate = min(max(self.abort_error_rate, 0.0), 1.0)

        if self.window_start or self.window_end:
            _parse_hhmm(self.window_start)
            _parse_hhmm(self.window_end)

    def in_allowed_window(self, now: datetime | None = None) -> bool:
        if not (self.window_start and self.window_end):
            return True
        now = now or datetime.now()
        start = _parse_hhmm(self.window_start)
        end = _parse_hhmm(self.window_end)
        cur = now.time()
        if start <= end:
            return start <= cur < end
        # Window wraps past midnight.
        return cur >= start or cur < end

    def authorizes(self, url: str) -> None:
        """Raise ValueError unless url is inside the engagement scope."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are permitted.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded credentials are not allowed.")
        if not parsed.hostname:
            raise ValueError("Target URL has no hostname.")
        host = parsed.hostname.lower().rstrip(".")
        if host not in self.authorized_hosts:
            raise ValueError(
                f"Target host '{host}' is NOT in the engagement scope. "
                f"Authorized hosts: {', '.join(self.authorized_hosts)}"
            )


def _parse_hhmm(value: str) -> dtime:
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", value.strip())
    if not m:
        raise ValueError(f"Time window value must be HH:MM (24h), got {value!r}")
    return dtime(int(m.group(1)), int(m.group(2)))


# ============================================================================
# HASH-CHAINED AUDIT LOG (tamper-evident)
# ============================================================================

class AuditLog:
    """
    Append-only JSONL audit trail. Each record embeds the SHA-256 of the
    previous record, so any later edit/deletion breaks the chain and is
    detectable with verify().
    """

    def __init__(self, path: str, engagement_id: str):
        self.path = Path(path)
        self.engagement_id = engagement_id
        self._lock = threading.Lock()
        self._prev_hash = "0" * 64
        # Seed prev_hash from an existing log so appends keep the chain intact.
        if self.path.exists():
            last = None
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last = line
            if last:
                self._prev_hash = hashlib.sha256(last.encode("utf-8")).hexdigest()

    def record(self, event: str, **fields):
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "engagement_id": self.engagement_id,
                "event": event,
                "prev_hash": self._prev_hash,
                **fields,
            }
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()

    def verify(self) -> bool:
        prev = "0" * 64
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False
            prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
        return True


# ============================================================================
# METRICS
# ============================================================================

@dataclass
class RequestResult:
    timestamp: str
    method: str
    url: str
    status: str
    status_code: str
    latency_ms: float
    response_size: int = 0
    error: str = ""


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.successful = 0
        self.failed = 0
        self.status_counts: dict = defaultdict(int)
        self.error_types: dict = defaultdict(int)
        self.latencies: list = []

    def add_success(self, status_code, latency):
        with self.lock:
            self.total += 1
            self.successful += 1
            self.status_counts[status_code] += 1
            self.latencies.append(latency)

    def add_failure(self, error_type, latency):
        with self.lock:
            self.total += 1
            self.failed += 1
            self.error_types[error_type] += 1
            self.latencies.append(latency)

    def snapshot(self) -> dict:
        with self.lock:
            latencies = sorted(self.latencies)
            error_rate = self.failed / self.total if self.total else 0.0
            return {
                "total": self.total,
                "successful": self.successful,
                "failed": self.failed,
                "error_rate": error_rate,
                "status_counts": dict(self.status_counts),
                "error_types": dict(self.error_types),
                "latencies": latencies,
            }


def percentile(ordered: list, pct: float) -> float:
    if not ordered:
        return 0.0
    idx = (pct / 100) * (len(ordered) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (idx - lo)


def knee_sample(latencies, threshold, win: int = 15):
    """The 'degradation knee': the first sample index at which the trailing
    `win`-sample P95 crosses `threshold`, i.e. where the target began to
    degrade. Input is CHRONOLOGICAL latencies (each window is sorted here for
    the percentile). Returns None if it never crossed / too few samples."""
    if not threshold or len(latencies) < 8:
        return None
    for i in range(len(latencies)):
        seg = sorted(latencies[max(0, i - win + 1):i + 1])
        if len(seg) >= 8 and percentile(seg, 95) > threshold:
            return i
    return None


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    """Shared aggregate pacing -- caps total request starts across all workers."""

    def __init__(self, rate):
        self.interval = 1.0 / max(1, rate)
        self.lock = threading.Lock()
        self.next_time = time.monotonic()

    def wait(self, stop_event) -> bool:
        while not stop_event.is_set():
            with self.lock:
                now = time.monotonic()
                if now >= self.next_time:
                    self.next_time = max(self.next_time + self.interval, now)
                    return True
                delay = self.next_time - now
            time.sleep(min(delay, 0.05))
        return False


# ============================================================================
# LOAD PATTERNS  (red-team resilience scenarios)
# ============================================================================
#
# A pattern function answers one question: at this instant, how many of the
# `base` workers should be ACTIVE?  It only shapes the *timing* of the load --
# it can never exceed the concurrency / RPS / duration ceilings enforced
# elsewhere, so every scenario below stays inside the hard safety caps. These
# are legitimate resilience-testing shapes (spike, oscillation, staircase,
# soak), not attack techniques.

def constant(elapsed, duration, base):
    """Flat, full load for the whole run -- baseline stress."""
    return base


def ramp_up(elapsed, duration, base):
    """Linear ramp 0 -> full: find the point where the target degrades."""
    return max(1, int(base * min(elapsed / duration, 1.0)))


def step(elapsed, duration, base):
    """Staircase ramp in 4 discrete levels -- isolate the step that breaks it."""
    frac = min(elapsed / duration, 1.0) if duration else 1.0
    levels = 4
    level = min(int(frac * levels) + 1, levels)
    return max(1, int(base * level / levels))


def spike(elapsed, duration, base):
    """Low baseline punctuated by short full-load bursts -- flash-crowd test."""
    if duration <= 0:
        return base
    low = max(1, int(base * 0.3))
    period = max(duration / 4.0, 1.0)          # 4 spikes across the run
    phase = (elapsed % period) / period
    return base if phase > 0.8 else low        # burst in the last 20% of each cycle


def wave(elapsed, duration, base):
    """Sinusoidal load, ~3 cycles -- sustained oscillating pressure."""
    frac = elapsed / duration if duration else 0.0
    # sin shifted so the run starts at the trough; swings 30% -> 100% of base
    amp = 0.35 * (1 + math.sin(2 * math.pi * 3 * frac - math.pi / 2))
    return max(1, int(base * (0.3 + amp)))


def soak(elapsed, duration, base):
    """Steady moderate load (~50%) -- endurance / resource-leak hunting."""
    return max(1, int(base * 0.5))


PATTERNS = {
    "constant": constant,
    "ramp-up": ramp_up,
    "step": step,
    "spike": spike,
    "wave": wave,
    "soak": soak,
}


# ============================================================================
# PER-REQUEST TEMPLATING
# ============================================================================
# Substitute a few tokens into the URL / body at request time. This is a
# load-realism / cache-busting aid (unique ids per request so a cache or CDN
# does not silently absorb the load and skew the numbers) -- not obfuscation:
# the deconfliction marker header is still attached to every request.

def render_tokens(text, seq):
    """Replace {{uuid}} {{seq}} {{rand}} {{ts}} in `text`. No-op if absent."""
    if not text or "{{" not in text:
        return text
    return (text
            .replace("{{uuid}}", uuid.uuid4().hex)
            .replace("{{seq}}", str(seq))
            .replace("{{rand}}", str(random.randint(0, 2_147_483_647)))
            .replace("{{ts}}", str(int(time.time() * 1000))))


# ============================================================================
# ENGINE
# ============================================================================

class LoadTestEngine:
    def __init__(self, config, roe: RulesOfEngagement, audit: AuditLog, result_queue):
        self.config = config
        self.roe = roe
        self.audit = audit
        self.result_queue = result_queue

        self.stop_event = threading.Event()
        self.finished_event = threading.Event()
        self.abort_reason = None

        self.metrics = Metrics()
        self.rate_limiter = RateLimiter(config["rps"])
        self.pattern = PATTERNS[config["pattern"]]
        self.start_time = None

        # multi-endpoint "user journey": round-robin over a list of steps.
        # falls back to the single url/method/body when none are supplied.
        endpoints = config.get("endpoints") or []
        if endpoints:
            self.steps = [(e.get("method", config["method"]), e["url"],
                           e.get("body", "")) for e in endpoints]
        else:
            self.steps = [(config["method"], config["url"], config["body"])]
        self._step_i = 0
        self._step_lock = threading.Lock()

        # per-request token templating (cache-busting / load realism)
        self.templating = bool(config.get("templating", False))
        self._seq = 0
        self._seq_lock = threading.Lock()

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent(roe.engagement_id),
            config["marker_header"]: roe.engagement_id,
        })
        self.session.headers.update(config["headers"])

    def start(self):
        self.start_time = time.monotonic()
        threading.Thread(target=self._run, daemon=True).start()
        threading.Thread(target=self._safety_monitor, daemon=True).start()

    def stop(self, reason="operator"):
        if not self.stop_event.is_set():
            self.abort_reason = self.abort_reason or reason
        self.stop_event.set()

    def _run(self):
        threads = []
        try:
            for _ in range(self.config["concurrency"]):
                t = threading.Thread(target=self._worker, daemon=True)
                t.start()
                threads.append(t)
            end = time.monotonic() + self.config["duration"]
            while time.monotonic() < end and not self.stop_event.is_set():
                time.sleep(0.1)
        finally:
            self.stop_event.set()
            for t in threads:
                t.join(timeout=2)
            self.session.close()
            self.finished_event.set()

    def _worker(self):
        base = self.config["concurrency"]
        while not self.stop_event.is_set():
            # Pattern gates whether this worker is "active" right now.
            elapsed = time.monotonic() - self.start_time
            active = self.pattern(elapsed, self.config["duration"], base)
            if base > active and (hash(threading.get_ident()) % base) >= active:
                time.sleep(0.1)
                continue
            if not self.rate_limiter.wait(self.stop_event):
                break
            if self.stop_event.is_set():
                break
            self._make_request()

    def _next_step(self):
        if len(self.steps) == 1:
            return self.steps[0]
        with self._step_lock:
            step = self.steps[self._step_i % len(self.steps)]
            self._step_i += 1
        return step

    def _make_request(self):
        method, url, body = self._next_step()
        if self.templating:
            with self._seq_lock:
                self._seq += 1
                seq = self._seq
            url = render_tokens(url, seq)
            body = render_tokens(body, seq)
        timeout = self.config["timeout"]
        started = time.perf_counter()
        try:
            resp = self.session.request(
                method=method,
                url=url,
                data=body if method in {"POST", "PUT", "PATCH"} else None,
                timeout=timeout,
                allow_redirects=False,
            )
            latency = (time.perf_counter() - started) * 1000
            size = len(resp.content or b"")
            self.metrics.add_success(resp.status_code, latency)
            result = RequestResult(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                method=method, url=url, status="success",
                status_code=str(resp.status_code), latency_ms=round(latency, 2),
                response_size=size,
            )
        except requests.Timeout:
            latency = (time.perf_counter() - started) * 1000
            self.metrics.add_failure("timeout", latency)
            result = RequestResult(datetime.now().isoformat(timespec="seconds"),
                                   method, url, "error", "", round(latency, 2),
                                   error="timeout")
        except requests.ConnectionError:
            latency = (time.perf_counter() - started) * 1000
            self.metrics.add_failure("connection_error", latency)
            result = RequestResult(datetime.now().isoformat(timespec="seconds"),
                                   method, url, "error", "", round(latency, 2),
                                   error="connection_error")
        except requests.RequestException as exc:
            latency = (time.perf_counter() - started) * 1000
            self.metrics.add_failure(type(exc).__name__, latency)
            result = RequestResult(datetime.now().isoformat(timespec="seconds"),
                                   method, url, "error", "", round(latency, 2),
                                   error=str(exc)[:200])
        self.result_queue.put(result)

    def _safety_monitor(self):
        """Auto-abort: stop the test if the target starts degrading."""
        min_sample = 20
        while not self.stop_event.is_set():
            time.sleep(1.0)
            snap = self.metrics.snapshot()
            if snap["total"] < min_sample:
                continue
            p95 = percentile(snap["latencies"], 95)
            if snap["error_rate"] > self.roe.abort_error_rate:
                self._trigger_abort(
                    f"error rate {snap['error_rate']:.0%} exceeded threshold "
                    f"{self.roe.abort_error_rate:.0%}")
                return
            if p95 > self.roe.abort_p95_latency_ms:
                self._trigger_abort(
                    f"P95 latency {p95:.0f}ms exceeded threshold "
                    f"{self.roe.abort_p95_latency_ms:.0f}ms")
                return

    def _trigger_abort(self, reason):
        self.abort_reason = f"AUTO-ABORT: {reason}"
        self.audit.record("auto_abort", reason=reason)
        self.stop_event.set()


# ============================================================================
# REPORTING
# ============================================================================

def build_report(roe: RulesOfEngagement, config, metrics: Metrics,
                 elapsed: float, abort_reason) -> dict:
    snap = metrics.snapshot()
    lat = snap["latencies"]
    # knee needs chronological order (snap["latencies"] is sorted)
    with metrics.lock:
        chrono = list(metrics.latencies)
    knee_i = knee_sample(chrono, roe.abort_p95_latency_ms)
    knee = None
    if knee_i is not None:
        n = len(chrono)
        knee = {
            "sample_index": knee_i,          # 0-based request where p95 crossed
            "of_total": n,
            "approx_elapsed_s": round(elapsed * (knee_i + 1) / n, 1) if n else 0,
            "p95_threshold_ms": roe.abort_p95_latency_ms,
        }
    return {
        "engagement_id": roe.engagement_id,
        "client": roe.client,
        "operator": roe.operator_label,
        "generated": datetime.now(timezone.utc).isoformat(),
        "target": config["url"],
        "method": config["method"],
        "pattern": config["pattern"],
        "planned_duration_s": config["duration"],
        "actual_duration_s": round(elapsed, 1),
        "concurrency": config["concurrency"],
        "rps_cap": config["rps"],
        "terminated_by": abort_reason or "completed normally",
        "totals": {
            "requests": snap["total"],
            "successful": snap["successful"],
            "failed": snap["failed"],
            "error_rate": round(snap["error_rate"], 4),
            "throughput_rps": round(snap["total"] / elapsed, 2) if elapsed else 0,
        },
        "latency_ms": {
            "min": round(min(lat), 2) if lat else 0,
            "p50": round(percentile(lat, 50), 2),
            "p90": round(percentile(lat, 90), 2),
            "p95": round(percentile(lat, 95), 2),
            "p99": round(percentile(lat, 99), 2),
            "max": round(max(lat), 2) if lat else 0,
            "mean": round(statistics.mean(lat), 2) if lat else 0,
            "stdev": round(statistics.pstdev(lat), 2) if len(lat) > 1 else 0,
        },
        "status_counts": snap["status_counts"],
        "error_types": snap["error_types"],
        "degradation_knee": knee,
    }


def print_report(report: dict):
    print("\n" + "=" * 60)
    print(f"  ENGAGEMENT REPORT  --  {report['engagement_id']}")
    print("=" * 60)
    print(f"  Client        : {report['client']}")
    print(f"  Operator      : {report['operator']}")
    print(f"  Target        : {report['method']} {report['target']}")
    print(f"  Pattern       : {report['pattern']}")
    print(f"  Duration      : {report['actual_duration_s']}s "
          f"(planned {report['planned_duration_s']}s)")
    print(f"  Terminated by : {report['terminated_by']}")
    t = report["totals"]
    print("-" * 60)
    print(f"  Requests      : {t['requests']}  "
          f"(ok {t['successful']} / fail {t['failed']})")
    print(f"  Error rate    : {t['error_rate']:.1%}")
    print(f"  Throughput    : {t['throughput_rps']} req/s")
    lat = report["latency_ms"]
    print("-" * 60)
    print(f"  Latency (ms)  : p50={lat['p50']}  p90={lat['p90']}  "
          f"p95={lat['p95']}  p99={lat['p99']}  max={lat['max']}")
    if report["status_counts"]:
        print(f"  Status codes  : {report['status_counts']}")
    if report["error_types"]:
        print(f"  Error types   : {report['error_types']}")
    knee = report.get("degradation_knee")
    if knee:
        print(f"  Degradation   : knee at request #{knee['sample_index']}"
              f"/{knee['of_total']} (~{knee['approx_elapsed_s']}s), "
              f"p95 crossed {knee['p95_threshold_ms']:.0f}ms")
    print("=" * 60 + "\n")


# ============================================================================
# CLI
# ============================================================================

def parse_headers(pairs) -> dict:
    headers = {}
    for item in pairs or []:
        if ":" not in item:
            raise ValueError(f"Invalid --header (use 'Name: value'): {item}")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Authorized red-team HTTP load/resilience tester.")
    ap.add_argument("--roe", required=True, help="Path to Rules of Engagement JSON.")
    ap.add_argument("--url", required=True, help="Target URL (must be in RoE scope).")
    ap.add_argument("--method", default="GET",
                    choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    ap.add_argument("--pattern", default="constant", choices=list(PATTERNS))
    ap.add_argument("--concurrency", type=int, help="Workers (default: RoE max).")
    ap.add_argument("--rps", type=int, help="Requests/sec cap (default: RoE max).")
    ap.add_argument("--duration", type=int, help="Seconds (default: RoE max).")
    ap.add_argument("--header", action="append", help="Extra header 'Name: value'.")
    ap.add_argument("--endpoint", action="append", metavar="'METHOD url'",
                    help="Journey hop 'METHOD url' or just 'url' (repeatable). "
                         "Turns the single-path load into a round-robin journey; "
                         "every hop is scope-checked.")
    ap.add_argument("--template", action="store_true",
                    help="Inject {{uuid}} {{seq}} {{rand}} {{ts}} tokens into the "
                         "URL/body per request (cache-bust).")
    ap.add_argument("--body", default="", help="Request body for POST/PUT/PATCH.")
    ap.add_argument("--audit-log", default="audit.log.jsonl")
    ap.add_argument("--report", default="", help="Write JSON report to this path.")
    ap.add_argument("--csv", default="", help="Write per-request CSV to this path.")
    ap.add_argument("--yes", action="store_true",
                    help="Skip the interactive authorization prompt.")
    args = ap.parse_args(argv)

    try:
        roe = RulesOfEngagement.load(args.roe)
        roe.authorizes(args.url)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[REFUSED] {exc}", file=sys.stderr)
        return 2

    if not roe.in_allowed_window():
        print(f"[REFUSED] Outside allowed test window "
              f"({roe.window_start}-{roe.window_end}).", file=sys.stderr)
        return 2

    # optional multi-endpoint journey -- parse and scope-check every hop
    endpoints = []
    for item in args.endpoint or []:
        parts = item.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in {
                "GET", "POST", "PUT", "PATCH", "DELETE"}:
            method, hop = parts[0].upper(), parts[1].strip()
        else:
            method, hop = args.method, item.strip()
        endpoints.append({"method": method, "url": hop, "body": args.body})
    try:
        for e in endpoints:
            roe.authorizes(e["url"])
    except ValueError as exc:
        print(f"[REFUSED] {exc}", file=sys.stderr)
        return 2

    concurrency = min(args.concurrency or roe.max_concurrency, roe.max_concurrency)
    rps = min(args.rps or roe.max_rps, roe.max_rps)
    duration = min(args.duration or roe.max_duration, roe.max_duration)

    try:
        headers = parse_headers(args.header)
    except ValueError as exc:
        print(f"[REFUSED] {exc}", file=sys.stderr)
        return 2
    if len(args.body.encode("utf-8")) > MAX_BODY_SIZE:
        print(f"[REFUSED] Body exceeds {MAX_BODY_SIZE} bytes.", file=sys.stderr)
        return 2

    config = {
        "url": args.url, "method": args.method, "pattern": args.pattern,
        "concurrency": concurrency, "rps": rps, "duration": duration,
        "timeout": roe.timeout, "headers": headers, "body": args.body,
        "marker_header": DEFAULT_MARKER_HEADER,
        "endpoints": endpoints, "templating": bool(args.template),
    }

    print("\n--- AUTHORIZED TEST CONFIRMATION ---")
    print(f"  Engagement : {roe.engagement_id}  ({roe.client})")
    print(f"  Operator   : {roe.operator_label}")
    print(f"  Target     : {args.method} {args.url}")
    print(f"  Load       : {concurrency} workers, <= {rps} req/s, {duration}s, "
          f"pattern={args.pattern}")
    if endpoints:
        print(f"  Journey    : {len(endpoints)} endpoints (round-robin) --")
        for e in endpoints:
            print(f"                 {e['method']} {e['url']}")
    if args.template:
        print("  Templating : on  ({{uuid}}/{{seq}}/{{rand}}/{{ts}} per request)")
    print(f"  Auto-abort : error>{roe.abort_error_rate:.0%} or "
          f"p95>{roe.abort_p95_latency_ms:.0f}ms")
    if roe.emergency_contact:
        print(f"  Emergency  : {roe.emergency_contact}")
    if not args.yes:
        ans = input("\nConfirm you are authorized to test this target [type YES]: ")
        if ans.strip() != "YES":
            print("[ABORTED] Not confirmed.")
            return 1

    audit = AuditLog(args.audit_log, roe.engagement_id)
    audit.record("test_start", operator=roe.operator_label,
                 target=args.url, method=args.method, pattern=args.pattern,
                 concurrency=concurrency, rps=rps, duration=duration,
                 endpoints=len(endpoints) or 1, templating=bool(args.template))

    result_queue = queue.Queue()
    engine = LoadTestEngine(config, roe, audit, result_queue)
    all_results = []
    print(f"\n[RUNNING] {roe.engagement_id}  (Ctrl+C to stop)\n")
    engine.start()

    try:
        while not engine.finished_event.is_set():
            _drain(result_queue, all_results)
            snap = engine.metrics.snapshot()
            el = time.monotonic() - engine.start_time
            sys.stdout.write(
                f"\r  {el:5.1f}s | req={snap['total']:<6} "
                f"ok={snap['successful']:<6} fail={snap['failed']:<5} "
                f"err={snap['error_rate']:.0%}   ")
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[STOPPING] operator interrupt...")
        engine.stop("operator interrupt (Ctrl+C)")
        engine.finished_event.wait(timeout=5)

    _drain(result_queue, all_results)
    elapsed = time.monotonic() - engine.start_time
    if engine.abort_reason:
        print(f"\n[!] {engine.abort_reason}")

    report = build_report(roe, config, engine.metrics, elapsed, engine.abort_reason)
    audit.record("test_end", terminated_by=report["terminated_by"],
                 totals=report["totals"])
    print_report(report)

    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  Report written : {args.report}")
    if args.csv:
        _write_csv(args.csv, all_results)
        print(f"  CSV written    : {args.csv}")
    print(f"  Audit log      : {args.audit_log} "
          f"(chain {'OK' if audit.verify() else 'BROKEN'})")
    return 0


def _drain(q, sink):
    while True:
        try:
            sink.append(q.get_nowait())
        except queue.Empty:
            return


def _write_csv(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "method", "url", "status", "status_code",
                    "latency_ms", "response_size", "error"])
        for r in results:
            w.writerow([r.timestamp, r.method, r.url, r.status, r.status_code,
                        r.latency_ms, r.response_size, r.error])


if __name__ == "__main__":
    raise SystemExit(main())
