from pathlib import Path

from app.ai_analysis import MockAIProvider, generate_ai_analysis
from app.cloud_loader import load_cloud_assets
from app.detector import detect_cloud_security_findings
from app.reporter import (
    generate_json_report,
    generate_markdown_report,
)


def test_securecloudai_end_to_end(tmp_path):
    data_path = Path("data/sample_cloud_assets.json")

    assets = load_cloud_assets(data_path)

    findings = detect_cloud_security_findings(assets)

    ai_analysis = generate_ai_analysis(
        findings,
        MockAIProvider(),
    )

    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    generate_json_report(
        findings,
        json_path,
        ai_analysis,
    )

    generate_markdown_report(
        findings,
        markdown_path,
        ai_analysis,
    )

    assert len(assets) == 5
    assert len(findings) == 5

    assert ai_analysis["provider"] == "mock"
    assert ai_analysis["ai_generated"] is True

    assert json_path.exists()
    assert markdown_path.exists()

    json_content = json_path.read_text(
        encoding="utf-8"
    )
    markdown_content = markdown_path.read_text(
        encoding="utf-8"
    )

    assert '"finding_count": 5' in json_content
    assert '"ai_analysis"' in json_content
    assert "AI-Assisted Analysis" in markdown_content
    assert "CLOUD-S3-001" in markdown_content