import json
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def build_report(
    findings: list[dict[str, Any]],
    ai_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a structured cloud security assessment report."""

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "low").lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    ordered_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(
            finding.get("severity", "low").lower(),
            0,
        ),
        reverse=True,
    )

    report = {
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "findings": ordered_findings,
    }

    if ai_analysis is not None:
        report["ai_analysis"] = ai_analysis

    return report


def generate_json_report(
    findings: list[dict[str, Any]],
    output_path: str | Path,
    ai_analysis: dict[str, Any] | None = None,
) -> Path:
    """Write the cloud security assessment as JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report = build_report(
        findings,
        ai_analysis,
    )

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return path


def generate_markdown_report(
    findings: list[dict[str, Any]],
    output_path: str | Path,
    ai_analysis: dict[str, Any] | None = None,
) -> Path:
    """Write the cloud security assessment as Markdown."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report = build_report(
        findings,
        ai_analysis,
    )

    severity_counts = report["severity_counts"]

    lines = [
        "# SecureCloudAI Security Assessment",
        "",
        f"**Total Findings:** {report['finding_count']}",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        f"| Critical | {severity_counts['critical']} |",
        f"| High | {severity_counts['high']} |",
        f"| Medium | {severity_counts['medium']} |",
        f"| Low | {severity_counts['low']} |",
        "",
    ]

    if ai_analysis is not None:
        lines.extend(
            [
                "## AI-Assisted Analysis",
                "",
                f"**Provider:** {ai_analysis.get('provider', 'unknown')}",
                "",
                "### Summary",
                "",
                ai_analysis.get("summary", ""),
                "",
                "### Evidence",
                "",
            ]
        )

        evidence = ai_analysis.get("evidence", [])

        if evidence:
            for rule_id in evidence:
                lines.append(f"- `{rule_id}`")
        else:
            lines.append("No evidence references provided.")

        lines.extend(
            [
                "",
                "### Recommendations",
                "",
            ]
        )

        recommendations = ai_analysis.get(
            "recommendations",
            [],
        )

        if recommendations:
            for recommendation in recommendations:
                lines.append(f"- {recommendation}")
        else:
            lines.append("No recommendations provided.")

        lines.append("")

    if not findings:
        lines.extend(
            [
                "No security findings were detected.",
                "",
            ]
        )

    for finding in report["findings"]:
        lines.extend(
            [
                f"## {finding['rule_id']}: {finding['title']}",
                "",
                f"- **Severity:** "
                f"{finding['severity'].upper()}",
                f"- **Asset ID:** {finding['asset_id']}",
                "",
                "### Description",
                "",
                finding["description"],
                "",
                "### Remediation",
                "",
                finding["remediation"],
                "",
            ]
        )

    with path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    return path