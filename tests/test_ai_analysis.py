import json

from app.ai_analysis import (
    AIProvider,
    MockAIProvider,
    OpenAIProvider,
    generate_ai_analysis,
)


def sample_findings():
    return [
        {
            "rule_id": "CLOUD-S3-001",
            "severity": "critical",
            "title": "Publicly accessible storage bucket",
            "description": "Bucket allows public access.",
            "remediation": "Disable public access.",
            "asset_id": "s3-001",
        },
        {
            "rule_id": "CLOUD-S3-002",
            "severity": "high",
            "title": "Storage encryption disabled",
            "description": "Encryption is disabled.",
            "remediation": "Enable encryption.",
            "asset_id": "s3-001",
        },
    ]


def test_mock_ai_provider():
    result = MockAIProvider().analyze_findings(
        sample_findings()
    )

    assert result["provider"] == "mock"
    assert result["ai_generated"] is True
    assert "CLOUD-S3-001" in result["evidence"]
    assert result["summary"]
    assert result["recommendations"]


def test_generate_ai_analysis():
    result = generate_ai_analysis(
        sample_findings(),
        MockAIProvider(),
    )

    assert result["provider"] == "mock"
    assert len(result["evidence"]) == 2


def test_openai_provider_requires_api_key(monkeypatch):
    monkeypatch.delenv(
        "OPENAI_API_KEY",
        raising=False,
    )

    try:
        OpenAIProvider()
    except ValueError as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:
        raise AssertionError(
            "OpenAIProvider should require an API key."
        )


class FakeResponse:
    output_text = json.dumps(
        {
            "summary": "Cloud assessment requires review.",
            "recommendations": [
                "Review the exposed resource.",
                "Enable appropriate security controls.",
            ],
        }
    )


class FakeResponses:
    def create(self, **kwargs):
        return FakeResponse()


class FakeClient:
    def __init__(self):
        self.responses = FakeResponses()


def test_openai_response_is_normalized(monkeypatch):
    monkeypatch.setenv(
        "OPENAI_API_KEY",
        "test-key",
    )

    provider = OpenAIProvider()

    provider.client = FakeClient()

    result = provider.analyze_findings(
        sample_findings()
    )

    assert result["provider"] == "openai"
    assert result["model"] == "gpt-5.6-luna"
    assert result["summary"] == (
        "Cloud assessment requires review."
    )
    assert len(result["recommendations"]) == 2