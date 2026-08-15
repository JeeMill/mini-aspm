import subprocess, os
from pathlib import Path

SCAN_DIR = Path("scans")


SCAN_DIR.mkdir(exist_ok=True)


def run_scan(name, command):
    print(f"[INFO] Running {name}...")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            print(f"[SUCCESS] {name} completed.")
        else:
            print(
                f"[WARNING] {name} exited with code "
                f"{result.returncode}"
            )

        if result.stderr:
            print(result.stderr)

        return result.returncode

    except FileNotFoundError:
        print(f"[ERROR] Could not run {name}")
        return -1

def run_all_scans():
    scans = [
        (
            "Gitleaks",
            [
                "gitleaks",
                "detect",
                "--source",
                ".",
                "--report-format",
                "json",
                "--report-path",
                "scans/gitleaks.json"
            ]
        ),
        (
            "Semgrep",
            [
                "semgrep",
                "scan",
                "--config",
                "auto",
                "--json-output",
                "scans/semgrep.json",
                "."
            ]
        ),
        (
            "OSV-Scanner",
            [
                "osv-scanner",
                "scan",
                "source",
                "-r",
                ".",
                "--format",
                "json",
                "--output",
                "scans/osv.json"
            ]
        ),
        (
            "Checkov",
            if os.name == "nt":
                checkov_command = [
                    "cmd",
                    "/c",
                    "checkov",
                    "-d",
                    "infrastructure",
                    "-o",
                    "json",
                    "--output-file-path",
                    "scans/checkov"
                ]
            else:
                checkov_command = [
                    "checkov",
                    "-d",
                    "infrastructure",
                    "-o",
                    "json"
                ],
            
        )
    ]


    for name, command in scans:
        run_scan(name, command)


if __name__ == "__main__":
    run_all_scans()