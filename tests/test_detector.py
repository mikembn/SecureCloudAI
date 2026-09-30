from app.detector import detect_cloud_security_findings


def test_detects_public_unencrypted_bucket():
    assets = [
        {
            "asset_id": "s3-001",
            "asset_type": "s3_bucket",
            "name": "public-data",
            "public_access": True,
            "encryption_enabled": False,
            "logging_enabled": False,
        }
    ]

    findings = detect_cloud_security_findings(assets)

    rule_ids = {finding["rule_id"] for finding in findings}

    assert "CLOUD-S3-001" in rule_ids
    assert "CLOUD-S3-002" in rule_ids
    assert "CLOUD-S3-003" in rule_ids


def test_detects_privileged_account_without_mfa():
    assets = [
        {
            "asset_id": "iam-001",
            "asset_type": "iam_user",
            "name": "admin",
            "mfa_enabled": False,
            "privileged": True,
            "active": True,
        }
    ]

    findings = detect_cloud_security_findings(assets)

    assert any(
        finding["rule_id"] == "CLOUD-IAM-001"
        for finding in findings
    )


def test_detects_internet_exposed_ssh():
    assets = [
        {
            "asset_id": "sg-001",
            "asset_type": "security_group",
            "name": "web-sg",
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "port": 22,
                    "source": "0.0.0.0/0",
                }
            ],
        }
    ]

    findings = detect_cloud_security_findings(assets)

    assert any(
        finding["rule_id"] == "CLOUD-NET-001"
        for finding in findings
    )


def test_secure_assets_produce_no_findings():
    assets = [
        {
            "asset_id": "s3-002",
            "asset_type": "s3_bucket",
            "name": "secure-data",
            "public_access": False,
            "encryption_enabled": True,
            "logging_enabled": True,
        },
        {
            "asset_id": "iam-002",
            "asset_type": "iam_user",
            "name": "developer",
            "mfa_enabled": True,
            "privileged": False,
            "active": True,
        },
    ]

    findings = detect_cloud_security_findings(assets)

    assert findings == []