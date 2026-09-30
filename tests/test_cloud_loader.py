import json

import pytest

from app.cloud_loader import load_cloud_assets


def test_load_cloud_assets(tmp_path):
    asset_file = tmp_path / "assets.json"

    assets = [
        {
            "asset_id": "s3-001",
            "asset_type": "s3_bucket",
            "name": "test-bucket",
        }
    ]

    asset_file.write_text(
        json.dumps(assets),
        encoding="utf-8",
    )

    result = load_cloud_assets(asset_file)

    assert len(result) == 1
    assert result[0]["asset_id"] == "s3-001"


def test_load_cloud_assets_requires_json_array(tmp_path):
    asset_file = tmp_path / "assets.json"

    asset_file.write_text(
        json.dumps({"asset_id": "s3-001"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_cloud_assets(asset_file)


def test_load_cloud_assets_rejects_missing_file(tmp_path):
    missing_file = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_cloud_assets(missing_file)