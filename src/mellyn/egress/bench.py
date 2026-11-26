"""
Deterministic egress scanner benchmark runner (`mellyn-bench`).

The corpus is a fixed set of regression cases (largely the scanner's own unit-test vectors). A PASS means no
regressions and the latency numbers are real; it is not a measurement of precision or recall on real traffic.

Strict DAG invariant: imports ONLY from `mellyn.core` and `mellyn.egress` (+ stdlib / pydantic).
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import statistics
import sys
import time
from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mellyn.core.normalize import JsonValue, exact_json_bytes
from mellyn.egress.scanner import scan_payload

BENCH_CANARY = "MELLYN_BENCH_CANARY_9944"


class BenchmarkSample(BaseModel):
    """One synthetic benchmark test vector with ground-truth expectations."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    sample_id: str
    category: Literal["benign", "canary", "secret", "high_entropy"]
    payload: JsonValue
    expect_clean: bool
    expect_canary: bool


class BenchmarkReport(BaseModel):
    """Deterministic precision/recall and latency summary from `mellyn-bench`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    total_samples: int = Field(ge=1)
    iterations: int = Field(ge=1)
    total_scans: int = Field(ge=1)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    canary_total: int = Field(ge=0)
    canary_detected: int = Field(ge=0)
    canary_recall: float = Field(ge=0.0, le=1.0)
    p50_us_per_kb: float = Field(ge=0.0)
    p99_us_per_kb: float = Field(ge=0.0)
    passed: bool


def _to_fullwidth_ascii(text: str) -> str:
    return "".join(chr(ord(ch) + 0xFEE0) if "!" <= ch <= "~" else ch for ch in text)


def build_benchmark_corpus() -> tuple[BenchmarkSample, ...]:
    """
    Build a deterministic synthetic corpus of benign payloads, obfuscated planted canaries,
    known API/PEM/URL credentials, and high-entropy tokens.

    Secret-shaped strings are constructed dynamically so repository secret scanners never treat
    benchmark fixtures as real credentials.
    """
    tag_insert = "".join(chr(0xE0000 + ord(ch)) for ch in "STEAL")
    openai_key = "sk-" + "proj-" + ("A9xQ7mL2pW4zK8rV" * 2)
    aws_key = "AKIA" + ("W7X8Y9Z0" * 2)
    github_pat = "gh" + "p_" + ("B2nM4qP6rS8tV0wX" * 2)
    obfuscated_key = "sk-\u200b" + "proj-" + ("C3dE5fG7hJ9kL1mN" * 2)
    url_secret = "https://" + "alice:top_secret_pw_99@" + "api.example.com/v1/export"
    pem_block = (
        "-----BEGIN RSA "
        + "PRIVATE KEY-----\n"
        + ("MIIEowIBAAKCAQEAt0FakeBenchmarkBodyOnly1234567890\n" * 3)
        + "-----END RSA "
        + "PRIVATE KEY-----"
    )
    high_ent_ctx = "api_" + "secret=" + "aZ9_kL2mP8qR4vW7xN3bY5cQ"
    high_ent_standalone = "qW8_mK2+pL9zR4xV7nB3cQ6tY"

    return (
        # Benign negative controls
        BenchmarkSample(
            sample_id="benign-prose",
            category="benign",
            payload="Summarize the quarterly architecture notes in docs/ARCHITECTURE.md for tomorrow's review.",
            expect_clean=True,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="benign-uuid",
            category="benign",
            payload="550e8400-e29b-41d4-a716-446655440000",
            expect_clean=True,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="benign-sha256",
            category="benign",
            payload="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            expect_clean=True,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="benign-json-result",
            category="benign",
            payload={"status": "ok", "items": ["alpha", "beta", "gamma"], "count": 3},
            expect_clean=True,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="benign-https-url",
            category="benign",
            payload={"uri": "https://docs.python.org/3/library/asyncio.html"},
            expect_clean=True,
            expect_canary=False,
        ),
        # Planted canary evasion variants
        BenchmarkSample(
            sample_id="canary-plain",
            category="canary",
            payload={"out": f"prefix {BENCH_CANARY} suffix"},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-lowercase",
            category="canary",
            payload={"out": BENCH_CANARY.lower()},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-mixedcase",
            category="canary",
            payload={"out": f"leak={BENCH_CANARY.title()}"},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-percent-encoded",
            category="canary",
            payload={"out": BENCH_CANARY.replace("_", "%5F")},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-zwsp-split",
            category="canary",
            payload={"out": "MELLYN_\u200bBENCH_\u200dCANARY_9944"},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-unicode-tags",
            category="canary",
            payload={"out": f"MELLYN_BENCH_{tag_insert}CANARY_9944"},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-fullwidth-nfkc",
            category="canary",
            payload={"out": _to_fullwidth_ascii(BENCH_CANARY)},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-dict-key",
            category="canary",
            payload={BENCH_CANARY: "value"},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-hex-lower",
            category="canary",
            payload={"out": BENCH_CANARY.encode("utf-8").hex()},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-base64-std",
            category="canary",
            payload={"out": base64.b64encode(BENCH_CANARY.encode("utf-8")).decode("ascii")},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-base64-offset",
            category="canary",
            payload={"out": base64.b64encode(b"x" + BENCH_CANARY.encode("utf-8") + b"y").decode("ascii")},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-reversed",
            category="canary",
            payload={"out": BENCH_CANARY[::-1]},
            expect_clean=False,
            expect_canary=True,
        ),
        BenchmarkSample(
            sample_id="canary-dot-interleaved",
            category="canary",
            payload={"out": ".".join(BENCH_CANARY)},
            expect_clean=False,
            expect_canary=True,
        ),
        # Known secrets & obfuscations
        BenchmarkSample(
            sample_id="secret-openai",
            category="secret",
            payload={"authorization": openai_key},
            expect_clean=False,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="secret-aws",
            category="secret",
            payload={"aws": aws_key},
            expect_clean=False,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="secret-github",
            category="secret",
            payload={"gh": github_pat},
            expect_clean=False,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="secret-zwsp-obfuscated",
            category="secret",
            payload={"obf": obfuscated_key},
            expect_clean=False,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="secret-url-userinfo",
            category="secret",
            payload={"url": url_secret},
            expect_clean=False,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="secret-pem-key",
            category="secret",
            payload={"pem": pem_block},
            expect_clean=False,
            expect_canary=False,
        ),
        # High-entropy credentials
        BenchmarkSample(
            sample_id="entropy-contextual",
            category="high_entropy",
            payload={"cfg": high_ent_ctx},
            expect_clean=False,
            expect_canary=False,
        ),
        BenchmarkSample(
            sample_id="entropy-standalone",
            category="high_entropy",
            payload={"blob": high_ent_standalone},
            expect_clean=False,
            expect_canary=False,
        ),
    )


def _percentile(sorted_values: Sequence[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if pct == 50.0:
        return float(statistics.median(sorted_values))
    idx = max(0, min(len(sorted_values) - 1, math.ceil((pct / 100.0) * len(sorted_values)) - 1))
    return float(sorted_values[idx])


def run_benchmark(*, iterations: int = 10) -> BenchmarkReport:
    """Execute the deterministic benchmark corpus across `iterations` passes and summarize accuracy + latency."""
    if iterations <= 0:
        raise ValueError("iterations must be positive.")

    corpus = build_benchmark_corpus()
    sample_sizes_kb = [max(len(exact_json_bytes(sample.payload)), 1) / 1024.0 for sample in corpus]

    # Warm regex compilation/imports before timing
    for sample in corpus:
        scan_payload(sample.payload, canary_tokens=(BENCH_CANARY,))

    tp = fp = tn = fn = 0
    canary_total = 0
    canary_detected = 0
    latencies_us_per_kb: list[float] = []

    for iteration in range(iterations):
        for sample, size_kb in zip(corpus, sample_sizes_kb, strict=True):
            start_ns = time.perf_counter_ns()
            result = scan_payload(sample.payload, canary_tokens=(BENCH_CANARY,))
            elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
            latencies_us_per_kb.append(elapsed_us / size_kb)

            if iteration == 0:
                if sample.expect_clean:
                    if result.clean:
                        tn += 1
                    else:
                        fp += 1
                else:
                    if not result.clean:
                        tp += 1
                    else:
                        fn += 1

                if sample.expect_canary:
                    canary_total += 1
                    if result.canary_matched:
                        canary_detected += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    canary_recall = canary_detected / canary_total if canary_total > 0 else 1.0

    latencies_sorted = sorted(latencies_us_per_kb)
    p50 = round(_percentile(latencies_sorted, 50.0), 3)
    p99 = round(_percentile(latencies_sorted, 99.0), 3)

    passed = canary_recall == 1.0 and fp == 0 and fn == 0
    return BenchmarkReport(
        total_samples=len(corpus),
        iterations=iterations,
        total_scans=len(corpus) * iterations,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 6),
        recall=round(recall, 6),
        canary_total=canary_total,
        canary_detected=canary_detected,
        canary_recall=round(canary_recall, 6),
        p50_us_per_kb=p50,
        p99_us_per_kb=p99,
        passed=passed,
    )


def render_benchmark_markdown(report: BenchmarkReport) -> str:
    """Format a `BenchmarkReport` as human-readable Markdown."""
    verdict = "PASS" if report.passed else "FAIL"
    return "\n".join(
        [
            f"# Mellyn Egress Scanner Benchmark ({verdict})",
            "",
            "- **Scope**: fixed regression corpus built from the scanner's own test cases; it catches regressions "
            "and measures latency, and is not an estimate of real-world precision or recall.",
            f"- **Corpus Size**: `{report.total_samples}` samples x `{report.iterations}` iterations "
            f"(`{report.total_scans}` scans)",
            f"- **Precision**: `{report.precision:.4f}` (TP={report.true_positives}, FP={report.false_positives})",
            f"- **Recall**: `{report.recall:.4f}` (FN={report.false_negatives}, TN={report.true_negatives})",
            f"- **Canary Recall**: `{report.canary_recall:.4f}` ({report.canary_detected}/{report.canary_total})",
            f"- **Latency (us/KB)**: `p50={report.p50_us_per_kb:.2f}`, `p99={report.p99_us_per_kb:.2f}`",
        ]
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mellyn-bench",
        description="Run deterministic accuracy and latency benchmarks for mellyn.egress.scanner.",
    )
    parser.add_argument("--iterations", type=int, default=10, help="Corpus repetitions for latency percentiles.")
    parser.add_argument("--json", action="store_true", help="Emit deterministic machine-readable JSON metrics.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `mellyn-bench`."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(iterations=args.iterations)
    except ValueError as exc:
        sys.stderr.write(f"mellyn-bench: invalid arguments: {exc}\n")
        return 2

    if args.json:
        sys.stdout.write(
            json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )
    else:
        sys.stdout.write(render_benchmark_markdown(report) + "\n")

    # `passed` requires full canary recall AND no false positives or negatives; a missed secret must fail the run.
    return 0 if report.passed else 1


__all__ = [
    "BENCH_CANARY",
    "BenchmarkReport",
    "BenchmarkSample",
    "build_benchmark_corpus",
    "main",
    "render_benchmark_markdown",
    "run_benchmark",
]


if __name__ == "__main__":
    raise SystemExit(main())
