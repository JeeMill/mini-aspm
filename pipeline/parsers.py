import json
from pathlib import Path

from pipeline.models import Finding

APPLICATION = "mini-aspm"

def load_json(path):
    with open(path, "r", encoding="utf-8-sig") as file:
        return json.load(file)


def normalize_severity(severity):
    if not severity:
        return "UNKNOWN"

    severity = str(severity).upper()

    if "CRITICAL" in severity:
        return "CRITICAL"

    if "HIGH" in severity:
        return "HIGH"

    if "MEDIUM" in severity:
        return "MEDIUM"

    if "LOW" in severity:
        return "LOW"

    if "INFO" in severity:
        return "INFO"

    return "UNKNOWN"



def parse_semgrep(path):
    data = load_json(path)

    findings = []

    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        severity = extra.get("severity", "UNKNOWN").upper()

        severity_mapping = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }

        severity = severity_mapping.get(severity, severity)

        cwe = metadata.get("cwe")

        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None

        file_path = result.get("path")

        line = result.get("start", {}).get("line")

        location = file_path

        if file_path and line:
            location = f"{file_path}:{line}"

        findings.append(
            Finding(
                application=APPLICATION,
                scanner="Semgrep",
                category="SAST",
                title=extra.get(
                    "message",
                    result.get("check_id", "Semgrep finding")
                ),
                severity=normalize_severity(severity),
                cwe=cwe,
                location=location,
                component=file_path,
            )
        )
    return findings

def parse_gitleaks(path):
    data = load_json(path)

    findings = []

    if not isinstance(data, list):
        return findings

    for result in data:
        file_path = result.get("File")
        line = result.get("StartLine")

        location = file_path

        if file_path and line:
            location = f"{file_path}:{line}"

        findings.append(
            Finding(
                application=APPLICATION,
                scanner="Gitleaks",
                category="SECRETS",
                title=result.get(
                    "Description",
                    result.get("RuleID", "Secret detected")
                ),
                severity="HIGH",
                location=location,
                component=file_path,
            )
        )

    return findings


def parse_checkov(path):
    data = load_json(path)

    findings = []

    reports = data if isinstance(data, list) else [data]

    for report in reports:
        results = report.get("results", {})

        for result in results.get("failed_checks", []):
            file_path = result.get("file_path")

            line_range = result.get("file_line_range")

            location = file_path

            if file_path and line_range:
                location = f"{file_path}:{line_range[0]}"

            findings.append(
                Finding(
                    application=APPLICATION,
                    scanner="Checkov",
                    category="IAC",
                    title=result.get(
                        "check_name",
                        result.get("check_id", "Checkov finding")
                    ),
                    severity=normalize_severity(
                        result.get("severity")
                    ),
                    location=location,
                    component=file_path,
                )
            )

    return findings

def parse_osv(path):
    data = load_json(path)

    findings = []

    for result in data.get("results", []):
        source = result.get("source", {})
        source_path = source.get("path")

        for package_result in result.get("packages", []):
            package = package_result.get("package", {})

            package_name = package.get("name")
            package_version = package.get("version")

            component = package_name

            if package_name and package_version:
                component = f"{package_name}@{package_version}"

            for vulnerability in package_result.get(
                "vulnerabilities", []
            ):
                vulnerability_id = vulnerability.get("id")

                aliases = vulnerability.get("aliases", [])

                cve = None

                if (
                    vulnerability_id
                    and vulnerability_id.startswith("CVE-")
                ):
                    cve = vulnerability_id
                else:
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            cve = alias
                            break

                database_specific = vulnerability.get(
                    "database_specific",
                    {}
                )

                severity = database_specific.get("severity")

                findings.append(
                    Finding(
                        application=APPLICATION,
                        scanner="OSV",
                        category="SCA",
                        title=vulnerability.get(
                            "summary",
                            vulnerability_id or
                            "Vulnerable dependency"
                        ),
                        severity=normalize_severity(severity),
                        cve=cve,
                        location=source_path,
                        component=component,
                    )
                )

    return findings

def parse_zap(path):
    data = load_json(path)

    findings = []

    for site in data.get("site", []):
        site_name = site.get("@name")

        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc")

            cwe_id = alert.get("cweid")

            cwe = None

            if cwe_id and str(cwe_id) != "0":
                cwe = f"CWE-{cwe_id}"

            instances = alert.get("instances", [])

            if not instances:
                instances = [{}]

            for instance in instances:
                location = (
                    instance.get("uri")
                    or instance.get("url")
                    or site_name
                )

                findings.append(
                    Finding(
                        application=APPLICATION,
                        scanner="OWASP ZAP",
                        category="DAST",
                        title=alert.get(
                            "alert",
                            "ZAP finding"
                        ),
                        severity=normalize_severity(risk),
                        cwe=cwe,
                        location=location,
                        component=site_name,
                    )
                )

    return findings