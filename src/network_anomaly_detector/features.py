"""Validated flow metadata and deterministic engineered features."""

from __future__ import annotations

import math

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, field_validator

RAW_FIELDS = (
    "duration_ms",
    "destination_port",
    "protocol",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "syn_flags",
    "ack_flags",
    "avg_packet_size",
    "active_mean_ms",
    "idle_mean_ms",
)
FEATURE_NAMES = RAW_FIELDS + (
    "total_packets",
    "total_bytes",
    "bytes_per_packet",
    "fwd_packet_ratio",
    "packets_per_second",
    "syn_packet_ratio",
)
LABELS = ("benign", "dos", "ddos", "port_scan", "brute_force", "botnet", "web_attack")


class FlowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duration_ms: float = Field(ge=0, le=3_600_000)
    destination_port: int = Field(ge=0, le=65535)
    protocol: int = Field(ge=0, le=255)
    fwd_packets: float = Field(ge=0, le=10_000_000)
    bwd_packets: float = Field(ge=0, le=10_000_000)
    fwd_bytes: float = Field(ge=0, le=10_000_000_000)
    bwd_bytes: float = Field(ge=0, le=10_000_000_000)
    syn_flags: float = Field(ge=0, le=10_000_000)
    ack_flags: float = Field(ge=0, le=10_000_000)
    avg_packet_size: float = Field(ge=0, le=10_000_000)
    active_mean_ms: float = Field(ge=0, le=3_600_000)
    idle_mean_ms: float = Field(ge=0, le=3_600_000)

    @field_validator(
        "duration_ms",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "syn_flags",
        "ack_flags",
        "avg_packet_size",
        "active_mean_ms",
        "idle_mean_ms",
    )
    @classmethod
    def finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("Flow feature must be finite")
        return value


def extract_features(flow: FlowRecord) -> np.ndarray:
    values = flow.model_dump()
    packets = flow.fwd_packets + flow.bwd_packets
    bytes_total = flow.fwd_bytes + flow.bwd_bytes
    engineered = (
        packets,
        bytes_total,
        bytes_total / max(packets, 1),
        flow.fwd_packets / max(packets, 1),
        packets / max(flow.duration_ms / 1000, 0.001),
        flow.syn_flags / max(packets, 1),
    )
    return np.asarray([values[name] for name in RAW_FIELDS] + list(engineered), dtype=np.float64)


def feature_matrix(flows: list[FlowRecord]) -> np.ndarray:
    if not flows:
        raise ValueError("At least one flow is required")
    return np.vstack([extract_features(flow) for flow in flows])
