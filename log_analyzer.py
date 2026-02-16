from collections import defaultdict
import argparse
from datetime import datetime


def write_report(log_file_path: str, threshold: int, failed_attempts: dict, suspicious: dict) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = "report.txt"

    with open(report_path, "w", encoding="utf-8") as report:
        report.write("Log Analyzer Report\n")
        report.write(f"Time: {timestamp}\n")
        report.write(f"Log file: {log_file_path}\n")
        report.write(f"Threshold: {threshold}\n\n")

        report.write("Failed login attempts per IP:\n")
        if not failed_attempts:
            report.write("(none found)\n")
        else:
            for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
                report.write(f"{ip}: {count}\n")

        report.write(f"\nSuspicious IP addresses (failed attempts >= {threshold}):\n")
        if not suspicious:
            report.write("(none)\n")
        else:
            for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
                report.write(f"{ip} -> {count} attempts\n")

    print(f"\nReport saved to: {report_path}")


def analyze_log_file(log_file_path: str, threshold: int) -> None:
    failed_attempts = defaultdict(int)

    # Parse the log file and count failed attempts per IP
    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                # Example: "Failed password ... from <IP> ..."
                if "Failed password" in line and " from " in line:
                    parts = line.split()
                    if "from" in parts:
                        from_idx = parts.index("from")
                        if from_idx + 1 < len(parts):
                            ip = parts[from_idx + 1]
                            failed_attempts[ip] += 1
    except FileNotFoundError:
        print(f"Log file '{log_file_path}' not found.")
        return

    # Print summary counts
    print("Failed login attempts per IP:")
    if not failed_attempts:
        print("(none found)")
    else:
        for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip}: {count}")

    # Filter suspicious IPs
    suspicious = {ip: count for ip, count in failed_attempts.items() if count >= threshold}

    print(f"\nSuspicious IP addresses (failed attempts >= {threshold}):")
    if not suspicious:
        print("(none)")
    else:
        for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip} -> {count} attempts")

    # Write report.txt
    write_report(log_file_path, threshold, dict(failed_attempts), suspicious)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious IP addresses")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum number of failed attempts to flag an IP (default: 3)",
    )
    args = parser.parse_args()

    analyze_log_file(args.log_file, args.threshold)


if __name__ == "__main__":
    main()