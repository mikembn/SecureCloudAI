import os
from pathlib import Path

from app.ai_analysis import (
    MockAIProvider,
    OpenAIProvider,
    generate_ai_analysis,
)
from app.cloud_loader import load_cloud_assets
from app.detector import detect_cloud_security_findings
from app.reporter import (
    generate_json_report,
    generate_markdown_report,
)


def get_ai_provider():
    """Select the AI provider from the environment."""

    provider_name = os.getenv(
        "SECURECLOUDAI_AI_PROVIDER",
        "mock",
    ).lower()

    if provider_name == "openai":
        return OpenAIProvider()

    return MockAIProvider()


def main() -> None:
    data_path = Path("data/sample_cloud_assets.json")
    reports_dir = Path("reports")

    assets = load_cloud_assets(data_path)

    findings = detect_cloud_security_findings(assets)

    ai_provider = get_ai_provider()

    ai_analysis = generate_ai_analysis(
        findings,
        ai_provider,
    )

    reports_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    json_path = reports_dir / "securecloudai_report.json"
    markdown_path = reports_dir / "securecloudai_report.md"

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

    print("SecureCloudAI Analysis Complete")
    print(f"Cloud assets analyzed: {len(assets)}")
    print(f"Security findings: {len(findings)}")
    print(f"AI provider: {ai_analysis['provider']}")
    print(f"AI summary: {ai_analysis['summary']}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")


if __name__ == "__main__":
    main()