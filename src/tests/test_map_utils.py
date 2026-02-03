import pandas as pd
from pathlib import Path
import tempfile

from src.map_utils import prepare_alerts_for_map


def test_prepare_alerts_for_map_basic():
    # Create a temporary CSV with lat/lon
    tmpdir = Path(tempfile.mkdtemp())
    csv_path = tmpdir / "alerts.csv"
    df = pd.DataFrame(
        [ 
            { 
                "timestamp": "2026-02-03T10:00:00", 
                "src_ip": "1.1.1.1", 
                "lat": 37.7749, 
                "lon": -122.4194, 
                "confidence": 90, 
            }, 
            { 
                "timestamp": "2026-02-03T11:00:00", 
                "src_ip": "2.2.2.2", 
                "lat": 51.5074, 
                "lon": -0.1278, 
                "confidence": 75, 
            }, 
        ] 
    )
    df.to_csv(csv_path, index=False)

    out = prepare_alerts_for_map(csv_path, enrich_missing=False, min_confidence=0)
    assert not out.empty
    assert "lat" in out.columns and "lon" in out.columns
    assert len(out) == 2
