"""Normalize locally obtained official CIC-IDS2017 flow CSVs; never reads PCAP payloads."""

import argparse
import csv
import hashlib
import math
from pathlib import Path

import pandas as pd

from network_anomaly_detector.features import RAW_FIELDS, FlowRecord

LABEL_MAP = {
    "BENIGN": "benign",
    "DDoS": "ddos",
    "PortScan": "port_scan",
    "Bot": "botnet",
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "Web Attack - Brute Force": "web_attack",
    "Web Attack - XSS": "web_attack",
    "Web Attack - Sql Injection": "web_attack",
}
COLUMNS = {
    "destination_port": "Destination Port",
    "protocol": "Protocol",
    "fwd_packets": "Total Fwd Packets",
    "bwd_packets": "Total Backward Packets",
    "fwd_bytes": "Total Length of Fwd Packets",
    "bwd_bytes": "Total Length of Bwd Packets",
    "syn_flags": "SYN Flag Count",
    "ack_flags": "ACK Flag Count",
    "avg_packet_size": "Average Packet Size",
    "active_mean_ms": "Active Mean",
    "idle_mean_ms": "Idle Mean",
    "duration_ms": "Flow Duration",
}


def prepare(source: Path, output: Path, append: bool = False) -> dict[str, int]:
    if not source.is_file() or source.stat().st_size > 2_000_000_000:
        raise ValueError("Source CSV missing or too large")
    output.parent.mkdir(parents=True, exist_ok=True)
    counts = {"accepted": 0, "unsupported_label": 0, "invalid": 0}
    with (
        source.open(newline="", encoding="utf-8-sig", errors="replace") as incoming,
        output.open("a" if append else "w", newline="", encoding="utf-8") as outgoing,
    ):
        reader = csv.DictReader(incoming)
        if reader.fieldnames is None:
            raise ValueError("CSV header missing")
        reader.fieldnames = [name.strip() for name in reader.fieldnames]
        required = set(COLUMNS.values()) | {"Label", "Source IP", "Destination IP", "Timestamp"}
        if not required.issubset(reader.fieldnames):
            raise ValueError("Required CIC-IDS2017 columns missing")
        writer = csv.DictWriter(outgoing, fieldnames=[*RAW_FIELDS, "group_id", "label"])
        if not append:
            writer.writeheader()
        for row in reader:
            label = LABEL_MAP.get((row["Label"] or "").strip())
            if label is None:
                counts["unsupported_label"] += 1
                continue
            try:
                values = {name: float(row[column]) for name, column in COLUMNS.items()}
                for name in ("duration_ms", "active_mean_ms", "idle_mean_ms"):
                    values[name] /= 1000  # CIC durations are microseconds.
                if not all(math.isfinite(value) for value in values.values()):
                    raise ValueError("Non-finite value")
                flow = FlowRecord.model_validate(values)
                source_ip = (row["Source IP"] or "").strip()
                destination_ip = (row["Destination IP"] or "").strip()
                if not source_ip or not destination_ip:
                    raise ValueError("Missing group identity")
                timestamp = pd.to_datetime(row["Timestamp"], errors="raise")
                if pd.isna(timestamp):
                    raise ValueError("Missing timestamp")
                bucket = timestamp.floor("min").isoformat()
                group_id = hashlib.sha256(
                    f"{source_ip}|{destination_ip}|{bucket}".encode()
                ).hexdigest()[:24]
                writer.writerow({**flow.model_dump(), "group_id": group_id, "label": label})
                counts["accepted"] += 1
            except (ValueError, TypeError, KeyError):
                counts["invalid"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, default=Path("data/processed/cic_flows.csv"))
    args = parser.parse_args()
    totals = {"accepted": 0, "unsupported_label": 0, "invalid": 0}
    for index, source in enumerate(args.input):
        counts = prepare(source, args.output, append=index > 0)
        for name, count in counts.items():
            totals[name] += count
    print(totals)


if __name__ == "__main__":
    main()
