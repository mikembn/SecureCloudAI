from typing import Any


def detect_cloud_security_findings(
    assets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Analyze cloud assets for security misconfigurations."""

    if not isinstance(assets, list):
        raise ValueError("Cloud assets must be provided as a list.")

    if not all(isinstance(asset, dict) for asset in assets):
        raise ValueError(
            "Each cloud asset must be a JSON object."
        )

    findings: list[dict[str, Any]] = []

    for asset in assets:
        asset_id = asset.get("asset_id", "unknown")
        asset_name = asset.get("name", "unknown")
        asset_type = asset.get("asset_type", "unknown")

        # Rule 1: Public S3 bucket
        if (
            asset_type == "s3_bucket"
            and asset.get("public_access") is True
        ):
            findings.append(
                {
                    "rule_id": "CLOUD-S3-001",
                    "severity": "critical",
                    "title": "Publicly accessible storage bucket",
                    "description": (
                        f"Storage bucket '{asset_name}' "
                        "allows public access."
                    ),
                    "remediation": (
                        "Disable public access and verify that "
                        "bucket access policies only allow "
                        "authorized principals."
                    ),
                    "asset_id": asset_id,
                }
            )

        # Rule 2: Unencrypted S3 bucket
        if (
            asset_type == "s3_bucket"
            and asset.get("encryption_enabled") is False
        ):
            findings.append(
                {
                    "rule_id": "CLOUD-S3-002",
                    "severity": "high",
                    "title": "Storage encryption disabled",
                    "description": (
                        f"Storage bucket '{asset_name}' "
                        "does not have encryption enabled."
                    ),
                    "remediation": (
                        "Enable server-side encryption using an "
                        "approved encryption key and verify that "
                        "new objects are encrypted."
                    ),
                    "asset_id": asset_id,
                }
            )

        # Rule 3: Logging disabled
        if (
            asset_type == "s3_bucket"
            and asset.get("logging_enabled") is False
        ):
            findings.append(
                {
                    "rule_id": "CLOUD-S3-003",
                    "severity": "medium",
                    "title": "Storage logging disabled",
                    "description": (
                        f"Storage bucket '{asset_name}' "
                        "does not have logging enabled."
                    ),
                    "remediation": (
                        "Enable access logging or an equivalent "
                        "centralized audit mechanism and verify "
                        "that logs are retained appropriately."
                    ),
                    "asset_id": asset_id,
                }
            )

        # Rule 4: Privileged IAM account without MFA
        if (
            asset_type == "iam_user"
            and asset.get("privileged") is True
            and asset.get("mfa_enabled") is False
        ):
            findings.append(
                {
                    "rule_id": "CLOUD-IAM-001",
                    "severity": "critical",
                    "title": "Privileged account without MFA",
                    "description": (
                        f"Privileged IAM user '{asset_name}' "
                        "does not have MFA enabled."
                    ),
                    "remediation": (
                        "Enable MFA for the privileged account "
                        "and verify that privileged access "
                        "requires the additional authentication factor."
                    ),
                    "asset_id": asset_id,
                }
            )

        # Rule 5: SSH exposed to the internet
        if asset_type == "security_group":
            for rule in asset.get("inbound_rules", []):
                if (
                    rule.get("protocol") == "tcp"
                    and rule.get("port") == 22
                    and rule.get("source") == "0.0.0.0/0"
                ):
                    findings.append(
                        {
                            "rule_id": "CLOUD-NET-001",
                            "severity": "high",
                            "title": "SSH exposed to the internet",
                            "description": (
                                f"Security group '{asset_name}' "
                                "allows SSH access from "
                                "0.0.0.0/0."
                            ),
                            "remediation": (
                                "Restrict SSH access to approved "
                                "management networks, VPN ranges, "
                                "or other explicitly authorized sources."
                            ),
                            "asset_id": asset_id,
                        }
                    )

    return findings