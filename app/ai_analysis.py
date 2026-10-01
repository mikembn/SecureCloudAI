import json
import os
from typing import Any

from openai import OpenAI


class AIProvider:
    """Interface for AI-assisted cloud security analysis."""

    def analyze_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        raise NotImplementedError


class MockAIProvider(AIProvider):
    """Deterministic provider for development and testing."""

    def analyze_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        critical_count = sum(
            1
            for finding in findings
            if finding.get("severity") == "critical"
        )

        high_count = sum(
            1
            for finding in findings
            if finding.get("severity") == "high"
        )

        summary = (
            f"Cloud security assessment identified "
            f"{len(findings)} findings, including "
            f"{critical_count} critical and "
            f"{high_count} high-severity findings."
        )

        recommendations = [
            finding["remediation"]
            for finding in findings
            if finding.get("remediation")
        ]

        return {
            "summary": summary,
            "evidence": [
                finding.get("rule_id")
                for finding in findings
                if finding.get("rule_id")
            ],
            "recommendations": recommendations,
            "provider": "mock",
            "ai_generated": True,
        }


class OpenAIProvider(AIProvider):
    """OpenAI-powered cloud security analysis."""

    def __init__(
        self,
        model: str = "gpt-5.6-luna",
    ) -> None:
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is not set."
            )

        self.client = OpenAI(api_key=api_key)
        self.model = model

    def analyze_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        prompt = (
            "You are a cloud security analysis assistant.\n\n"
            "Analyze only the security findings provided below.\n"
            "Do not invent facts or additional findings.\n"
            "Clearly distinguish observed evidence from "
            "recommendations.\n\n"
            "Return valid JSON with these fields:\n"
            "- summary: concise assessment summary\n"
            "- recommendations: array of recommended actions\n\n"
            f"Security findings:\n"
            f"{json.dumps(findings, indent=2)}"
        )

        response = self.client.responses.create(
            model=self.model,
            input=prompt,
        )

        raw_output = response.output_text.strip()

        try:
            result = json.loads(raw_output)
        except json.JSONDecodeError:
            result = {
                "summary": raw_output,
                "recommendations": [],
            }

        if not isinstance(result, dict):
            result = {
                "summary": raw_output,
                "recommendations": [],
            }

        summary = result.get("summary", "")
        recommendations = result.get(
            "recommendations",
            [],
        )

        if not isinstance(summary, str):
            summary = str(summary)

        if not isinstance(recommendations, list):
            recommendations = []

        recommendations = [
            str(item)
            for item in recommendations
        ]

        return {
            "summary": summary,
            "evidence": [
                finding.get("rule_id")
                for finding in findings
                if finding.get("rule_id")
            ],
            "recommendations": recommendations,
            "provider": "openai",
            "model": self.model,
            "ai_generated": True,
        }


def generate_ai_analysis(
    findings: list[dict[str, Any]],
    provider: AIProvider,
) -> dict[str, Any]:
    """Generate AI-assisted analysis for security findings."""

    return provider.analyze_findings(findings)