#!/usr/bin/env python3
"""
dns-propagation-checker
=======================

Check DNS propagation of a record across dozens of public resolvers worldwide.

Useful after:
- Changing nameservers
- Updating A/AAAA records during a cutover
- Rotating MX records
- Publishing TXT records for SPF/DKIM/DMARC
- Adding CAA records

Compares responses from multiple resolvers, flags mismatches, optionally polls
until the record has fully propagated.

Author: Aslam Ahamed <https://www.linkedin.com/in/aslam-ahamed/>
License: MIT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import dns.resolver
    import dns.exception
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: dnspython is required. Install with: pip install dnspython\n"
    )
    sys.exit(2)


# Curated list of public DNS resolvers spread across providers and regions.
# Each entry: (label, ip, provider, region)
DEFAULT_RESOLVERS: list[tuple[str, str, str, str]] = [
    ("Google-1",        "8.8.8.8",         "Google",      "Global"),
    ("Google-2",        "8.8.4.4",         "Google",      "Global"),
    ("Cloudflare-1",    "1.1.1.1",         "Cloudflare",  "Global"),
    ("Cloudflare-2",    "1.0.0.1",         "Cloudflare",  "Global"),
    ("Quad9",           "9.9.9.9",         "Quad9",       "Global"),
    ("Quad9-Secured",   "149.112.112.112", "Quad9",       "Global"),
    ("OpenDNS-1",       "208.67.222.222",  "OpenDNS",     "US"),
    ("OpenDNS-2",       "208.67.220.220",  "OpenDNS",     "US"),
    ("AdGuard",         "94.140.14.14",    "AdGuard",     "Global"),
    ("CleanBrowsing",   "185.228.168.9",   "CleanBrows.", "Global"),
    ("Level3-1",        "4.2.2.1",         "CenturyLink", "US"),
    ("Level3-2",        "4.2.2.2",         "CenturyLink", "US"),
    ("Yandex",          "77.88.8.8",       "Yandex",      "RU"),
    ("Neustar-1",       "64.6.64.6",       "Neustar",     "US"),
    ("Comodo",          "8.26.56.26",      "Comodo",      "US"),
    ("DNS.WATCH",       "84.200.69.80",    "DNS.WATCH",   "DE"),
    ("Hurricane",       "74.82.42.42",     "HE.net",      "US"),
    ("SafeDNS",         "195.46.39.39",    "SafeDNS",     "Global"),
]


SUPPORTED_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA", "PTR", "SRV"]


@dataclass
class QueryResult:
    resolver: str
    ip: str
    provider: str
    region: str
    record_type: str
    domain: str
    values: list[str] = field(default_factory=list)
    ttl: Optional[int] = None
    rtt_ms: Optional[float] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and len(self.values) > 0

    @property
    def fingerprint(self) -> str:
        """Canonical, comparable representation of the response set."""
        if self.error is not None:
            return f"ERROR:{self.error}"
        return "|".join(sorted(self.values)) or "NODATA"


def query_one(
    resolver_entry: tuple[str, str, str, str],
    domain: str,
    record_type: str,
    timeout: float,
) -> QueryResult:
    label, ip, provider, region = resolver_entry
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [ip]
    r.timeout = timeout
    r.lifetime = timeout

    result = QueryResult(
        resolver=label,
        ip=ip,
        provider=provider,
        region=region,
        record_type=record_type,
        domain=domain,
    )

    start = time.perf_counter()
    try:
        answer = r.resolve(domain, record_type, raise_on_no_answer=False)
        elapsed = (time.perf_counter() - start) * 1000.0
        result.rtt_ms = round(elapsed, 1)

        if answer.rrset is None:
            result.error = "NODATA"
            return result

        result.ttl = answer.rrset.ttl
        for rdata in answer:
            result.values.append(rdata.to_text())
    except dns.resolver.NXDOMAIN:
        result.error = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result.error = "NODATA"
    except dns.resolver.NoNameservers:
        result.error = "SERVFAIL"
    except dns.exception.Timeout:
        result.error = "TIMEOUT"
    except Exception as exc:  # noqa: BLE001
        result.error = f"ERR:{exc.__class__.__name__}"
    return result


def run_checks(
    domain: str,
    record_type: str,
    resolvers: list[tuple[str, str, str, str]],
    timeout: float,
    workers: int,
) -> list[QueryResult]:
    results: list[QueryResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(query_one, r, domain, record_type, timeout) for r in resolvers
        ]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    # Preserve resolver list order
    order = {entry[0]: i for i, entry in enumerate(resolvers)}
    results.sort(key=lambda x: order.get(x.resolver, 999))
    return results


# --------- Reporting ---------

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _fmt_values(values: list[str], max_width: int = 48) -> str:
    if not values:
        return "-"
    text = ", ".join(values)
    if len(text) > max_width:
        text = text[: max_width - 1] + "…"
    return text


def print_report(
    domain: str,
    record_type: str,
    results: list[QueryResult],
    use_color: bool = True,
) -> dict:
    """Print a human table and return a summary dict."""
    def c(color: str) -> str:
        return color if use_color else ""

    # Consensus calculation
    fingerprints: dict[str, int] = {}
    for r in results:
        fingerprints[r.fingerprint] = fingerprints.get(r.fingerprint, 0) + 1
    if fingerprints:
        consensus_fp, consensus_count = max(fingerprints.items(), key=lambda x: x[1])
    else:
        consensus_fp, consensus_count = "", 0

    ok_count = sum(1 for r in results if r.ok)
    err_count = len(results) - ok_count
    mismatch_count = sum(
        1 for r in results if r.ok and r.fingerprint != consensus_fp
    )

    print(f"\n{c(BOLD)}DNS Propagation Report{c(RESET)}")
    print(f"  Domain : {c(CYAN)}{domain}{c(RESET)}")
    print(f"  Type   : {c(CYAN)}{record_type}{c(RESET)}")
    print(f"  Checked: {len(results)} resolvers\n")

    header = f"{'RESOLVER':<16} {'IP':<17} {'PROVIDER':<13} {'REG':<4} {'TTL':>6} {'RTT':>7}  VALUES"
    print(c(DIM) + header + c(RESET))
    print(c(DIM) + "-" * len(header) + c(RESET))

    for r in results:
        if r.error:
            status_color = c(RED)
            val_text = r.error
        elif r.fingerprint == consensus_fp:
            status_color = c(GREEN)
            val_text = _fmt_values(r.values)
        else:
            status_color = c(YELLOW)
            val_text = _fmt_values(r.values)
        ttl = str(r.ttl) if r.ttl is not None else "-"
        rtt = f"{r.rtt_ms:.0f}ms" if r.rtt_ms is not None else "-"
        print(
            f"{r.resolver:<16} {r.ip:<17} {r.provider:<13} {r.region:<4} "
            f"{ttl:>6} {rtt:>7}  {status_color}{val_text}{c(RESET)}"
        )

    # Summary
    print()
    if err_count == 0 and mismatch_count == 0:
        print(
            f"{c(GREEN)}✓ Fully propagated — all {len(results)} resolvers agree.{c(RESET)}"
        )
    else:
        print(f"{c(BOLD)}Summary:{c(RESET)}")
        print(
            f"  {c(GREEN)}agree with consensus{c(RESET)}: {consensus_count}/{len(results)}"
        )
        if mismatch_count:
            print(f"  {c(YELLOW)}mismatched responses{c(RESET)}: {mismatch_count}")
        if err_count:
            print(f"  {c(RED)}errors / no answer{c(RESET)}: {err_count}")

    summary = {
        "domain": domain,
        "type": record_type,
        "total": len(results),
        "ok": ok_count,
        "errors": err_count,
        "mismatches": mismatch_count,
        "consensus_count": consensus_count,
        "consensus_values": (
            []
            if not consensus_fp or consensus_fp.startswith("ERROR:")
            else consensus_fp.split("|")
        ),
        "fully_propagated": err_count == 0 and mismatch_count == 0,
        "results": [asdict(r) for r in results],
    }
    return summary


# --------- CLI ---------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dns-propagation-checker",
        description="Check DNS propagation across many public resolvers.",
    )
    p.add_argument("domain", help="Domain name to query, e.g. example.com")
    p.add_argument(
        "-t",
        "--type",
        default="A",
        choices=SUPPORTED_TYPES,
        help="Record type to query (default: A)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Per-resolver timeout in seconds (default: 3.0)",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=16,
        help="Parallel query workers (default: 16)",
    )
    p.add_argument(
        "--watch",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Poll mode: re-run every SECONDS until fully propagated (0 = off)",
    )
    p.add_argument(
        "--max-wait",
        type=int,
        default=1800,
        metavar="SECONDS",
        help="Maximum total wait time for --watch (default: 1800)",
    )
    p.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="VALUE",
        help="Expected value(s). Exit non-zero if any resolver doesn't return it. "
             "Can be passed multiple times.",
    )
    p.add_argument(
        "--resolvers",
        help="Comma-separated list of resolver IPs to use instead of defaults",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary (disables colored table)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    return p


def resolvers_from_cli(csv_list: Optional[str]) -> list[tuple[str, str, str, str]]:
    if not csv_list:
        return DEFAULT_RESOLVERS
    out: list[tuple[str, str, str, str]] = []
    for i, ip in enumerate(x.strip() for x in csv_list.split(",") if x.strip()):
        out.append((f"custom-{i+1}", ip, "custom", "-"))
    return out


def _expect_check(results: list[QueryResult], expected: list[str]) -> bool:
    """Return True if every resolver returned a superset of expected values."""
    if not expected:
        return True
    wanted = set(expected)
    for r in results:
        if r.error:
            return False
        got = set(r.values)
        # Be lenient about TXT records that arrive quoted
        got_unquoted = {v.strip('"') for v in got}
        if not wanted.issubset(got) and not wanted.issubset(got_unquoted):
            return False
    return True


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    resolvers = resolvers_from_cli(args.resolvers)
    use_color = sys.stdout.isatty() and not args.no_color and not args.json

    started = time.time()
    while True:
        results = run_checks(
            args.domain, args.type, resolvers, args.timeout, args.workers
        )
        summary = print_report(args.domain, args.type, results, use_color=use_color) \
            if not args.json else {
                "domain": args.domain,
                "type": args.type,
                "total": len(results),
                "ok": sum(1 for r in results if r.ok),
                "errors": sum(1 for r in results if not r.ok),
                "results": [asdict(r) for r in results],
            }

        expected_met = _expect_check(results, args.expect)

        if args.json:
            summary["expected"] = args.expect
            summary["expected_met"] = expected_met
            print(json.dumps(summary, indent=2))

        fully = summary.get("fully_propagated", False) if not args.json \
            else (summary["errors"] == 0)

        if args.watch <= 0:
            if args.expect and not expected_met:
                return 1
            return 0 if fully else 2

        if fully and expected_met:
            return 0

        if time.time() - started > args.max_wait:
            sys.stderr.write(
                f"\nTimed out after {args.max_wait}s waiting for propagation.\n"
            )
            return 3

        time.sleep(args.watch)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
