# Log Analyzer (Brute-Force Detection Tool)

A Python-based security tool that analyzes authentication logs, detects brute-force login attempts, and generates investigation reports.

## Why I built this
SOC analysts monitor logs to detect suspicious activity. This project simulates that workflow by parsing failed login attempts and flagging suspicious IP addresses.

## Features
- Counts failed login attempts per IP
- Flags suspicious IPs using configurable threshold
- Generates timestamped investigation report
- Command-line interface support

## Usage

```bash
python3 log_analyzer.py sample.log --threshold 3
