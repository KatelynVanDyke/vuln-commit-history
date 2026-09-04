from __future__ import annotations

TRANSITION_LABEL = "TRANSITION_LABEL"
FIX = "FIX"
OTHER = "OTHER"

PROVENANCE_NATURAL_HISTORY = "natural_history"
PROVENANCE_PRIMEVUL_PAIRED = "primevul_paired"

SLICE_OFFSET = "SLICE_OFFSET"

METADATA_COLUMNS = [
    "sample_id",
    "anchor_id",
    "project",
    "file_path",
    "source_commit",
    "target_commit",
    "source_timestamp",
    "target_timestamp",
    "cve_ids",
    "provenance",
    SLICE_OFFSET,
    TRANSITION_LABEL,
]
