import numpy as np
import pytest
from pydantic import ValidationError

from network_anomaly_detector.features import FEATURE_NAMES, FlowRecord, extract_features


def test_flow_features(flow: FlowRecord) -> None:
    vector = extract_features(flow)
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[FEATURE_NAMES.index("total_packets")] == 18
    assert np.all(np.isfinite(vector))


def test_malformed_flow_rejected(flow: FlowRecord) -> None:
    with pytest.raises(ValidationError):
        FlowRecord.model_validate({**flow.model_dump(), "destination_port": 70000})
    with pytest.raises(ValidationError):
        FlowRecord.model_validate({**flow.model_dump(), "fwd_packets": float("inf")})
