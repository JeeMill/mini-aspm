import json
from pathlib import Path

from pipeline.parsers import (
    parse_semgrep,
    parse_osv,
    parse_gitleaks,
    parse_checkov,
    parse_zap,
)


ROOT_DIR = Path(__file__).resolve().parent.parent
SCAN_DIR = ROOT_DIR / "scans" / "normalized"

OUTPUT_FILE = SCAN_DIR / "normalized_findings.json"


SCANNERS = [
    ("semgrep.json", parse_semgrep),
    ("osv.json", parse_osv),
    ("gitleaks.json", parse_gitleaks),
    ("checkov.json", parse_checkov),
    ("zap.json", parse_zap),
]


def main():
    all_findings = []

    for filename, parser in SCANNERS:
        scan_file = SCAN_DIR / filename

        if not scan_file.exists():
            print(f"[SKIP] {filename} not found")
            continue

        try:
            findings = parser(scan_file)

            all_findings.extend(findings)

            print(
                f"[OK] {filename}: "
                f"{len(findings)} findings"
            )

        except Exception as error:
            print(
                f"[ERROR] Could not parse "
                f"{filename}: {error}"
            )

    output = [
        finding.to_dict()
        for finding in all_findings
    ]

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(output, file, indent=2)

    print()
    print(f"Total findings: {len(output)}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()