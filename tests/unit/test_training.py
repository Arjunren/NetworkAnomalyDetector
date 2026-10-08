import csv
from pathlib import Path

import numpy as np

from network_anomaly_detector.artifact import load_model
from network_anomaly_detector.features import LABELS, RAW_FIELDS
from network_anomaly_detector.training import (
    TrainingConfig,
    calculate_metrics,
    split_indices,
    train,
)


def test_group_split_disjoint() -> None:
    labels = np.asarray([int(label != "benign") for label in LABELS for _ in range(30)])
    groups = np.asarray([f"{label}-{index}" for label in LABELS for index in range(30)])
    partitions = split_indices(labels, groups, TrainingConfig())
    sets = [set(groups[part]) for part in partitions]
    assert not sets[0] & sets[1]
    assert not sets[0] & sets[2]
    assert not sets[1] & sets[2]


def test_metrics_include_false_rates() -> None:
    result = calculate_metrics(np.asarray([0, 0, 1, 1]), np.asarray([0.1, 0.9, 0.2, 0.8]), 0.5)
    assert result["false_positive_rate"] == 0.5
    assert result["false_negative_rate"] == 0.5


def test_training_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "flows.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*RAW_FIELDS, "group_id", "label"])
        writer.writeheader()
        for label_index, label in enumerate(LABELS):
            for group in range(30):
                writer.writerow(
                    {
                        "duration_ms": 100 + group,
                        "destination_port": 80 + label_index,
                        "protocol": 6,
                        "fwd_packets": 10 + label_index + group / 10,
                        "bwd_packets": 4 + label_index,
                        "fwd_bytes": 500 + label_index * 100 + group,
                        "bwd_bytes": 300 + label_index * 100,
                        "syn_flags": label_index,
                        "ack_flags": 2,
                        "avg_packet_size": 64 + group / 5,
                        "active_mean_ms": 50 + group,
                        "idle_mean_ms": 20 + group,
                        "group_id": f"{label}-{group}",
                        "label": label,
                    }
                )
    config = tmp_path / "training.json"
    config.write_text(Path("configs/training.json").read_text(encoding="utf-8"), encoding="utf-8")
    artifact = tmp_path / "model.json"
    report = train(source, artifact, config)
    assert report["test_metrics"]["pr_auc"] >= 0
    assert load_model(artifact).version == "1.0.0"
