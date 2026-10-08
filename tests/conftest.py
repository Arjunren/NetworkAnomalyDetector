from pathlib import Path

import numpy as np
import pytest

from network_anomaly_detector.artifact import Model, load_model, save_model
from network_anomaly_detector.features import FEATURE_NAMES, FlowRecord


@pytest.fixture
def flow() -> FlowRecord:
    return FlowRecord(
        duration_ms=1000,
        destination_port=443,
        protocol=6,
        fwd_packets=10,
        bwd_packets=8,
        fwd_bytes=1200,
        bwd_bytes=800,
        syn_flags=2,
        ack_flags=3,
        avg_packet_size=100,
        active_mean_ms=50,
        idle_mean_ms=25,
    )


@pytest.fixture
def model(tmp_path: Path) -> Model:
    size = len(FEATURE_NAMES)
    payload = {
        "features": list(FEATURE_NAMES),
        "means": [0.0] * size,
        "scales": [1.0] * size,
        "pca_mean": [0.0] * size,
        "components": np.eye(size)[:4].tolist(),
        "score_quantiles": np.linspace(0, 10000, 101).tolist(),
        "threshold": 1000.0,
        "version": "test-1",
    }
    artifact = tmp_path / "model.json"
    save_model(artifact, payload)
    return load_model(artifact)
