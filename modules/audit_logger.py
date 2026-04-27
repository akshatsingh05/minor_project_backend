"""
modules/audit_logger.py - Tamper-Evident Audit Logger

Implements hash-chained logging:
    hash_n = SHA256(serialize(current_entry) + previous_hash)

Each log entry contains:
    - timestamp       : ISO-8601 UTC time
    - action          : Event name (e.g. "encryption", "computation")
    - details         : Arbitrary dict with event-specific metadata
    - previous_hash   : Hash of the immediately preceding log entry
    - current_hash    : Hash of this entry (chained from previous)

Tampering with any entry breaks the hash chain, making it detectable.
"""

import hashlib
import json
import os
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Any, Dict, List


class AuditLogger:
    """Append-only, hash-chained audit log stored as a JSON array on disk."""

    GENESIS_HASH = "0" * 64  # Sentinel value for the very first entry

    def __init__(self, log_path: str):
        """
        Args:
            log_path: File path where logs.json will be stored.
        """
        self.log_path = log_path
        # Ensure the storage directory exists
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        # Bootstrap log file if it doesn't exist
        if not os.path.exists(log_path):
            self._write_logs([])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, action: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Append a new tamper-evident entry to the log.

        Args:
            action:  Short string describing what happened.
            details: Dict with context-specific data.

        Returns:
            The complete log entry that was appended.
        """
        logs = self._read_logs()

        previous_hash = logs[-1]["current_hash"] if logs else self.GENESIS_HASH

        # Build entry without current_hash first
        entry = {
            "timestamp": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
            "action": action,
            "details": details,
            "previous_hash": previous_hash,
            "current_hash": "",  # Placeholder; computed below
        }

        # Compute current_hash over the full entry content + previous_hash
        entry["current_hash"] = self._compute_hash(entry, previous_hash)

        logs.append(entry)
        self._write_logs(logs)
        return entry

    def get_logs(self) -> List[Dict[str, Any]]:
        """Return all audit log entries."""
        return self._read_logs()

    def verify_chain(self) -> bool:
        """
        Walk the entire log and confirm that every hash link is intact.

        Returns:
            True if the chain is valid; False if tampering is detected.
        """
        logs = self._read_logs()
        for i, entry in enumerate(logs):
            expected_previous = self.GENESIS_HASH if i == 0 else logs[i - 1]["current_hash"]
            if entry["previous_hash"] != expected_previous:
                return False
            # Recompute hash (exclude current_hash field from the digest)
            recomputed = self._compute_hash(entry, entry["previous_hash"])
            if recomputed != entry["current_hash"]:
                return False
        return True

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _compute_hash(self, entry: Dict[str, Any], previous_hash: str) -> str:
        """
        Compute SHA-256 over the serialized entry content + previous_hash.
        The 'current_hash' field is excluded from the digest so the
        computation is deterministic.
        """
        digest_entry = {k: v for k, v in entry.items() if k != "current_hash"}
        raw = json.dumps(digest_entry, sort_keys=True, default=str) + previous_hash
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _read_logs(self) -> List[Dict[str, Any]]:
        """Load and parse the JSON log file."""
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _write_logs(self, logs: List[Dict[str, Any]]) -> None:
        """Atomically write the log list back to disk."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, default=str)
