from app.detector import detect_cloud_security_findings


REQUIRED_FIELDS = {
    "rule_id",
    "severity",
    "title",
    "description",
    "remediation",
    "asset_id",
}


def test_security_findings_have_required_fields():
    assets = [
        {
            "asset_id": "s3-001",
            "asset_type": "s3_bucket",
            "name": "public-data",
            "public_access": True,
            "encryption_enabled": False,
            "logging_enabled": False,
        },
        {
            "asset_id": "iam-001",
            "asset_type": "iam_user",
            "name": "admin",
            "mfa_enabled": False,
            "privileged": True,
            "active": True,
        },
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
        },
    ]

    findings = detect_cloud_security_findings(assets)

    assert findings

    for finding in findings:
        assert REQUIRED_FIELDS.issubset(finding.keys())
        assert finding["rule_id"]
        assert finding["severity"]
        assert finding["title"]
        assert finding["description"]
        assert finding["remediation"]
        assert finding["asset_id"]