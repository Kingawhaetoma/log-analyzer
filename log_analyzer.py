#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple


# ---------- Parsing ----------

# Common patterns:
# Linux auth.log / sshd:
# "Feb 16 00:12:34 host sshd[123]: Failed password for invalid user admin from 192.168.1.10 port 55222 ssh2"
LINUX_SSH_FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*Failed password.* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)

# Windows-ish sample line (you can adapt later):
# "2026-02-16T00:12:34Z FAILED_LOGIN src_ip=10.0.0.5 user=Administrator"
WINDOWS_FAILED_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*(FAILED_LOGIN|Failed login).*?(src_ip=|from )(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)


MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


@dataclass(frozen=True)
class Event:
    ts: datetime
    ip: str
    raw: str


def parse_linux_timestamp(month: str, day: str, hhmmss: str, year: int) -> datetime:
    return datetime(year, MONTHS[month], int(day), int(hhmmss[0:2]), int(hhmmss[3:5]), int(hhmmss[6:8]))


def parse_events(lines: List[str], assumed_year: int) -> List[Event]:
    events: List[Event] = []
    for line in lines:
        line = line.rstrip("\n")

        m = LINUX_SSH_FAILED_RE.match(line)
        if m:
            ts = parse_linux_timestamp(m["mon"], m["day"], m["time"], assumed_year)
            events.append(Event(ts=ts, ip=m["ip"], raw=line))
            continue

        w = WINDOWS_FAILED_RE.match(line)
        if w:
            ts = datetime.strptime(w["iso"], "%Y-%m-%dT%H:%M:%SZ")
            events.append(Event(ts=ts, ip=w["ip"], raw=line))
            continue

    return events


# ---------- Detection ----------

def severity(count: int, window_minutes: int, rate: float) -> str:
    """
    Simple scoring:
    - HIGH: very frequent or high volume
    - MED: moderate volume/rate
    - LOW: everything else
    """
    if count >= 20 or rate >= 3.0:
        return "HIGH"
    if count >= 10 or rate >= 1.0:
        return "MEDIUM"
    return "LOW"


def analyze(events: List[Event], threshold: int, window_minutes: int) -> Dict:
    """
    Detect IPs with >= threshold failed attempts within a sliding time window.
    """
    events_sorted = sorted(events, key=lambda e: e.ts)
    by_ip: Dict[str, List[Event]] = {}
    for e in events_sorted:
        by_ip.setdefault(e.ip, []).append(e)

    suspicious: Dict[str, Dict] = {}
    window = timedelta(minutes=window_minutes)

    for ip, ip_events in by_ip.items():
        # sliding window pointers
        i = 0
        best_count = 0
        best_start: Optional[datetime] = None
        best_end: Optional[datetime] = None

        for j in range(len(ip_events)):
            while ip_events[j].ts - ip_events[i].ts > window:
                i += 1
            count = j - i + 1
            if count > best_count:
                best_count = count
                best_start = ip_events[i].ts
                best_end = ip_events[j].ts

        if best_count >= threshold and best_start and best_end:
            duration_sec = max((best_end - best_start).total_seconds(), 1.0)
            rate_per_min = (best_count / duration_sec) * 60.0
            suspicious[ip] = {
                "ip": ip,
                "count_in_window": best_count,
                "window_minutes": window_minutes,
                "window_start": best_start.isoformat(sep=" "),
                "window_end": best_end.isoformat(sep=" "),
                "rate_per_min": round(rate_per_min, 2),
                "severity": severity(best_count, window_minutes, rate_per_min),
            }

    summary = {
        "total_events": len(events),
        "unique_source_ips": len(by_ip),
        "suspicious_ips": len(suspicious),
    }

    # Top talkers (total count)
    top_ips = sorted(((ip, len(v)) for ip, v in by_ip.items()), key=lambda x: x[1], reverse=True)[:10]

    return {
        "summary": summary,
        "top_ips": [{"ip": ip, "total_failed": total} for ip, total in top_ips],
        "suspicious": sorted(suspicious.values(), key=lambda x: x["count_in_window"], reverse=True),
    }


# ---------- Output ----------

def ensure_output_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_txt(report: Dict, outdir: str, log_path: str, threshold: int, window_minutes: int) -> str:
    ensure_output_dir(outdir)
    outpath = os.path.join(outdir, "report.txt")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(outpath, "w", encoding="utf-8") as f:
        f.write("Log Analyzer Report\n")
        f.write(f"Generated: {now}\n")
        f.write(f"Log file: {log_path}\n")
        f.write(f"Threshold: {threshold} within {window_minutes} minutes\n\n")

        f.write("Summary\n")
        for k, v in report["summary"].items():
            f.write(f"- {k}: {v}\n")

        f.write("\nTop IPs (by total failed attempts)\n")
        for item in report["top_ips"]:
            f.write(f"- {item['ip']}: {item['total_failed']}\n")

        f.write("\nSuspicious IPs (window-based)\n")
        if not report["suspicious"]:
            f.write("(none)\n")
        else:
            for s in report["suspicious"]:
                f.write(
                    f"- {s['ip']} | {s['severity']} | "
                    f"{s['count_in_window']} fails | {s['rate_per_min']}/min | "
                    f"{s['window_start']} → {s['window_end']}\n"
                )

    return outpath


def write_json(report: Dict, outdir: str) -> str:
    ensure_output_dir(outdir)
    outpath = os.path.join(outdir, "report.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return outpath


def write_csv(report: Dict, outdir: str) -> str:
    ensure_output_dir(outdir)
    outpath = os.path.join(outdir, "suspicious.csv")
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "severity", "count_in_window", "window_minutes", "rate_per_min", "window_start", "window_end"])
        for s in report["suspicious"]:
            w.writerow([s["ip"], s["severity"], s["count_in_window"], s["window_minutes"], s["rate_per_min"], s["window_start"], s["window_end"]])
    return outpath


# ---------- CLI ----------

def main() -> None:
    parser = argparse.ArgumentParser(description="Detect brute-force login attempts from auth logs.")
    parser.add_argument("log_file", help="Path to log file (e.g., auth.log, sample.log)")
    parser.add_argument("--threshold", type=int, default=8, help="Minimum failed attempts to flag (default: 8)")
    parser.add_argument("--window-minutes", type=int, default=10, help="Sliding time window in minutes (default: 10)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Assumed year for non-ISO logs (default: current year)")
    parser.add_argument("--outdir", default="output", help="Output directory for reports (default: output)")
    args = parser.parse_args()

    try:
        with open(args.log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"❌ Log file not found: {args.log_file}")
        return

    events = parse_events(lines, assumed_year=args.year)
    report = analyze(events, threshold=args.threshold, window_minutes=args.window_minutes)

    # Terminal summary
    print("\nSummary:")
    for k, v in report["summary"].items():
        print(f"- {k}: {v}")

    print("\nSuspicious IPs:")
    if not report["suspicious"]:
        print("(none)")
    else:
        for s in report["suspicious"]:
            print(f"{s['ip']} | {s['severity']} | {s['count_in_window']} fails | {s['rate_per_min']}/min")

    txt_path = write_txt(report, args.outdir, args.log_file, args.threshold, args.window_minutes)
    json_path = write_json(report, args.outdir)
    csv_path = write_csv(report, args.outdir)

    print(f"\n✅ Wrote: {txt_path}")
    print(f"✅ Wrote: {json_path}")
    print(f"✅ Wrote: {csv_path}")


if __name__ == "__main__":
    main()