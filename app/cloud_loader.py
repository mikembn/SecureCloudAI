import json
from pathlib import Path
from typing import Any


def load_cloud_assets(
    file_path: str | Path,
) -> list[dict[str, Any]]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Cloud asset file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            "Cloud asset file must contain a JSON array."
        )

    if not all(isinstance(asset, dict) for asset in data):
        raise ValueError(
            "Each cloud asset must be a JSON object."
        )

    return data