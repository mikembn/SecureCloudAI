import json

from app.reporter import (
    build_report,
    generate_json_report,
    generate_markdown_report,
)


def sample_findings():
    return [
        {
            "rule_id": "CLOUD-S3-001",
            "severity": "critical",
            "title": "Publicly accessible storage bucket",
            "description": "Bucket is publicly accessible.",
            "remediation": "Disable public access.",
            "asset_id": "s3-001",
        },
        {
            "rule_id": "CLOUD-S3-003",
            "severity": "medium",
            "title": "Storage logging disabled",
            "description": "Logging is disabled.",
            "remediation": "Enable logging.",
            "asset_id": "s3-001",
        },
    ]


def test_build_report_counts_severity():
    report = build_report(sample_findings())

    assert report["finding_count"] == 2
    assert report["severity_counts"]["critical"] == 1
    assert report["severity_counts"]["medium"] == 1


def test_build_report_orders_findings_by_severity():
    report = build_report(sample_findings())

    assert report["findings"][0]["severity"] == "critical"
    assert report["findings"][1]["severity"] == "medium"


def test_generate_json_report(tmp_path):
    output = tmp_path / "report.json"

    result = generate_json_report(
        sample_findings(),
        output,
    )

    assert result == output
    assert output.exists()

    data = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert data["finding_count"] == 2


def test_generate_markdown_report(tmp_path):
    output = tmp_path / "report.md"

    result = generate_markdown_report(
        sample_findings(),
        output,
    )

    assert result == output
    assert output.exists()

    content = output.read_text(
        encoding="utf-8"
    )

    assert "# SecureCloudAI Security Assessment" in content
    assert "CLOUD-S3-001" in content
    assert "Disable public access." in content