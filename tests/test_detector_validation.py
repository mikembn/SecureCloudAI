import pytest

from app.detector import detect_cloud_security_findings


def test_detector_rejects_non_list_input():
    with pytest.raises(ValueError):
        detect_cloud_security_findings(
            {"asset_id": "s3-001"}
        )


def test_detector_rejects_non_dictionary_assets():
    with pytest.raises(ValueError):
        detect_cloud_security_findings(
            [
                {
                    "asset_id": "s3-001",
                    "asset_type": "s3_bucket",
                },
                "invalid-asset",
            ]
        )