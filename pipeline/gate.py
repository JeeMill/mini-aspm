import json, sys
from pathlib import Path

RESULTS_FILE = Path("scans/normalized_findings.json")

BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}

def load_findings():
    if not RESULTS_FILE.exists():
        print(f"[ERROR] Results file not found: {RESULTS_FILE}")
        sys.exit(1)

    try:
        with RESULTS_FILE.open("r", encoding="utf-8-sig") as file:
            findings = json.load(file)

    except json.JSONDecodeError as error:
        print(f"[ERROR] Could not parse normalized findings: {error}")
        sys.exit(1)

    if not isinstance(findings, list):
        print("[ERROR] Normalized findings must be a JSON array.")
        sys.exit(1)

    return findings


def get_blocking_findings(findings):
    blocking_findings = []

    for finding in findings:
        severity = finding.get("severity", "").upper()
        status = finding.get("status", "").lower()

        if severity in BLOCKING_SEVERITIES:
            blocking_findings.append(finding)

    return blocking_findings


def print_finding(finding):
    print(
        f"  [{finding.get('severity', 'UNKNOWN')}] "
        f"{finding.get('scanner', 'Unknown Scanner')} - "
        f"{finding.get('category', 'Unknown Category')}"
    )

    print(f"    Location: {finding.get('location', 'Unknown')}")
    print(f"    Finding: {finding.get('title', 'No title')}")

def main():
    findings = load_findings()

    blocking_findings = get_blocking_findings(findings)

    print("\n=== Mini-ASPM Security Gate ===")
    print(f"Total findings: {len(findings)}")
    print(f"Blocking findings: {len(blocking_findings)}")

    if blocking_findings:
        print("\n[FAIL] Security gate failed.\n")

        for finding in blocking_findings:
            print_finding(finding)

        print(f'\n{len(blocking_findings)} findings violate security policy')

        sys.exit(1)

    print("\n[PASS] Security gate passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()