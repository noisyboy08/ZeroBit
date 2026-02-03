import pandas as pd
from pathlib import Path
import tempfile

from src.map_utils import prepare_alerts_for_map


def test_render_threat_map_data_path():
    tmpdir = Path(tempfile.mkdtemp())
    csv_path = tmpdir / "alerts.csv"
    # minimal lat/lon data
    df = pd.DataFrame([
        {"timestamp": "2026-02-03T12:00:00", "src_ip": "3.3.3.3", "lat": 40.7128, "lon": -74.0060, "confidence": 80}
    ])
    df.to_csv(csv_path, index=False)

    # prepare_alerts_for_map should return the same data when enrichment disabled
    out = prepare_alerts_for_map(csv_path, enrich_missing=False, min_confidence=0)
    assert not out.empty
    assert out.iloc[0]["src_ip"] == "3.3.3.3"
