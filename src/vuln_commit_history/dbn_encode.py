from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pandas as pd

from .constants import METADATA_COLUMNS, SLICE_OFFSET, TRANSITION_LABEL
from .io import read_json, read_jsonl, write_json


def feature_name(raw: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_").upper()
    return f"CT__{normalized}"


def parse_change_frequency(path: str | Path) -> dict[str, int]:
    """Presence (0/1) representation of each Coming change type, matching the sibling
    repo's ``dataset.parse_change_frequency`` default."""
    payload = read_json(path)
    counts: Counter[str] = Counter()
    for entry in payload.get("frequencyParent", []):
        raw = str(entry["c"])
        counts[feature_name(raw)] += int(entry["f"])
    return {name: int(count > 0) for name, count in counts.items()}


def build_long_table(
    transitions_path: str | Path,
    coming_output_dir: str | Path,
    output_csv: str | Path,
    metadata_json: str | Path,
    min_support: int = 1,
) -> pd.DataFrame:
    transitions = read_jsonl(transitions_path)
    coming_root = Path(coming_output_dir)
    raw_rows: list[dict] = []
    exclusions: list[dict] = []
    support: Counter[str] = Counter()

    for transition in transitions:
        frequency_file = coming_root / transition["sample_id"] / "change_frequency.json"
        if not frequency_file.is_file():
            exclusions.append({"sample_id": transition["sample_id"], "reason": "missing Coming output"})
            continue
        features = parse_change_frequency(frequency_file)
        support.update(features.keys())
        raw_rows.append(
            {
                "sample_id": transition["sample_id"],
                "anchor_id": transition["anchor_id"],
                "project": transition["project"],
                "file_path": transition["file_path"],
                "source_commit": transition["source_commit"],
                "target_commit": transition["target_commit"],
                "source_timestamp": transition.get("source_timestamp", ""),
                "target_timestamp": transition.get("target_timestamp", ""),
                "cve_ids": ";".join(transition["cve_ids"]),
                "provenance": transition["provenance"],
                SLICE_OFFSET: transition[SLICE_OFFSET],
                TRANSITION_LABEL: transition[TRANSITION_LABEL],
                **features,
            }
        )

    kept_features = sorted(name for name, count in support.items() if count >= min_support)
    rows = [
        {**{key: raw[key] for key in METADATA_COLUMNS}, **{f: raw.get(f, 0) for f in kept_features}}
        for raw in raw_rows
    ]
    frame = pd.DataFrame(rows, columns=METADATA_COLUMNS + kept_features)
    destination = Path(output_csv)
    destination.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(destination, index=False)
    write_json(
        metadata_json,
        {
            "min_support": min_support,
            "feature_columns": kept_features,
            "metadata_columns": METADATA_COLUMNS,
            "transitions": len(frame),
            "anchors": int(frame["anchor_id"].nunique()) if not frame.empty else 0,
            "exclusions": exclusions,
        },
    )
    return frame


def build_wide_two_slice_table(long_table: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    rows: list[dict] = []
    for anchor_id, group in long_table.groupby("anchor_id"):
        ordered = group.sort_values(SLICE_OFFSET).reset_index(drop=True)
        for i in range(1, len(ordered)):
            previous_row = ordered.iloc[i - 1]
            current_row = ordered.iloc[i]
            row = {
                "anchor_id": anchor_id,
                "project": current_row["project"],
                "slice_offset_t0": previous_row[SLICE_OFFSET],
                "slice_offset_t1": current_row[SLICE_OFFSET],
                f"{TRANSITION_LABEL}__t0": previous_row[TRANSITION_LABEL],
                f"{TRANSITION_LABEL}__t1": current_row[TRANSITION_LABEL],
            }
            for feature in feature_columns:
                row[f"{feature}__t0"] = int(previous_row.get(feature, 0))
                row[f"{feature}__t1"] = int(current_row.get(feature, 0))
            rows.append(row)
    return pd.DataFrame(rows)
