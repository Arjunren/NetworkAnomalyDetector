"""Train a benign baseline, report metrics, and score network flows."""

import argparse
import json
from pathlib import Path

from network_anomaly_detector.artifact import load_model
from network_anomaly_detector.features import FlowRecord
from network_anomaly_detector.training import train


def main() -> None:
    parser = argparse.ArgumentParser(description="Network anomaly detection")
    commands = parser.add_subparsers(dest="command", required=True)
    training = commands.add_parser("train")
    training.add_argument("--dataset", type=Path, required=True)
    training.add_argument("--model", type=Path, default=Path("models/model.json"))
    training.add_argument("--config", type=Path, default=Path("configs/training.json"))
    training.add_argument("--version", default="1.0.0")
    inference = commands.add_parser("predict")
    inference.add_argument("--model", type=Path, default=Path("models/model.json"))
    inference.add_argument(
        "--flow", type=Path, required=True, help="Local JSON file with a flow record"
    )
    evaluation = commands.add_parser("evaluate")
    evaluation.add_argument("--metadata", type=Path, default=Path("models/model.metadata.json"))
    args = parser.parse_args()
    if args.command == "train":
        result = train(args.dataset, args.model, args.config, args.version)
    elif args.command == "predict":
        flow = FlowRecord.model_validate_json(args.flow.read_text(encoding="utf-8"))
        result = load_model(args.model).predict(flow)
    else:
        result = json.loads(args.metadata.read_text(encoding="utf-8"))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
