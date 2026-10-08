"""Generate synthetic flow summaries for smoke tests, never a benchmark."""

import argparse
import csv
import random
from pathlib import Path

from network_anomaly_detector.features import LABELS, RAW_FIELDS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/processed/synthetic.csv"))
    args = parser.parse_args()
    rng = random.Random(42)  # noqa: S311 - deterministic synthetic fixtures only
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*RAW_FIELDS, "group_id", "label"])
        writer.writeheader()
        for label_index, label in enumerate(LABELS):
            for group in range(60 if label == "benign" else 20):
                for repetition in range(2):
                    factor = label_index + 1
                    writer.writerow(
                        {
                            "duration_ms": 1000 + group * 10 + rng.uniform(0, 100),
                            "destination_port": 80 + label_index + rng.randint(0, 2),
                            "protocol": 6,
                            "fwd_packets": 8 * factor + repetition + rng.randint(0, 4),
                            "bwd_packets": 4 * factor + rng.randint(0, 4),
                            "fwd_bytes": 1200 * factor + group + rng.randint(0, 300),
                            "bwd_bytes": 800 * factor + group + rng.randint(0, 200),
                            "syn_flags": factor + rng.randint(0, 2),
                            "ack_flags": factor + 1 + rng.randint(0, 2),
                            "avg_packet_size": 64 + factor + rng.uniform(0, 15),
                            "active_mean_ms": 40 + factor + rng.uniform(0, 15),
                            "idle_mean_ms": 50 + factor + rng.uniform(0, 15),
                            "group_id": f"{label}-{group}",
                            "label": label,
                        }
                    )
    print(args.output)


if __name__ == "__main__":
    main()
