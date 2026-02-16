# Log Analyzer (SOC Security Tool)

Python-based security log analyzer that detects brute-force login attacks and generates SOC-ready incident reports.

## Features

- Brute force detection
- Threat severity scoring
- MITRE ATT&CK mapping
- JSON, CSV, and TXT reporting
- Automated CI testing

## Technologies

- Python
- pytest
- GitHub Actions
- Security log analysis

## Example

```bash
python3 log_analyzer.py sample.log --threshold 4 --window-minutes 10
