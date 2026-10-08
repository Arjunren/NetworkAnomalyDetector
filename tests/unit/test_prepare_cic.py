import csv
from pathlib import Path

from scripts.prepare_cic import COLUMNS, prepare


def test_official_adapter_normalizes_without_payloads(tmp_path: Path) -> None:
    source = tmp_path / "cic.csv"
    fields = [*COLUMNS.values(), "Label", "Source IP", "Destination IP", "Timestamp"]
    values = {name: "10" for name in COLUMNS.values()}
    values.update(
        {
            "Label": "DDoS",
            "Source IP": "192.0.2.1",
            "Destination IP": "198.51.100.2",
            "Timestamp": "2017-07-07 08:42:00",
        }
    )
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(values)
    output = tmp_path / "normalized.csv"
    counts = prepare(source, output)
    assert counts == {"accepted": 1, "unsupported_label": 0, "invalid": 0}
    with output.open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["label"] == "ddos"
    assert float(row["duration_ms"]) == 0.01
    assert "192.0.2.1" not in output.read_text(encoding="utf-8")
