"""
modules/data_handler.py - Data Persistence and CSV Processing Module

Responsibilities:
    - Parse uploaded CSV files and extract a validated numeric column
    - Append single encrypted values to the storage CSV
    - Overwrite the storage CSV with a full dataset
    - Load stored encrypted values back into memory for computation
"""

import os
import io
from typing import List, Optional, Tuple

import pandas as pd


class DataHandler:
    """Manages reading and writing of encrypted values in data.csv."""

    COLUMN_NAME = "encrypted_value"  # Header used in the storage CSV

    def __init__(self, data_path: str):
        """
        Args:
            data_path: Path to the CSV file used for persistent storage.
        """
        self.data_path = data_path
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        # Bootstrap empty CSV if it doesn't exist
        if not os.path.exists(data_path):
            self._init_csv()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_csv(
        self, file_obj, column: str
    ) -> Tuple[Optional[List[float]], Optional[str]]:
        """
        Parse an uploaded CSV file and extract a numeric column.

        Args:
            file_obj: A file-like object (from Flask request.files).
            column:   The column name the user wants to process.

        Returns:
            (values, None)        on success
            (None, error_message) on failure
        """
        try:
            content = file_obj.read()
            df = pd.read_csv(io.BytesIO(content))
        except Exception as exc:
            return None, f"Could not parse CSV: {exc}"

        if df.empty:
            return None, "The uploaded CSV file is empty."

        if column not in df.columns:
            available = ", ".join(df.columns.tolist())
            return None, f"Column '{column}' not found. Available columns: {available}"

        series = df[column]

        # Attempt numeric conversion
        numeric_series = pd.to_numeric(series, errors="coerce")
        if numeric_series.isna().all():
            return None, f"Column '{column}' contains no numeric values."

        # Drop rows that couldn't be converted (NaN)
        valid = numeric_series.dropna().tolist()
        if not valid:
            return None, f"Column '{column}' has no valid numeric rows after cleaning."

        return valid, None

    def append_value(self, encrypted_value: float) -> None:
        """
        Append a single encrypted value to the storage CSV.

        Args:
            encrypted_value: The encrypted numeric value to persist.
        """
        existing = self.load_values()
        existing.append(encrypted_value)
        self.write_values(existing)

    def write_values(self, encrypted_values: List[float]) -> None:
        """
        Overwrite the storage CSV with a fresh list of encrypted values.

        Args:
            encrypted_values: Complete list of encrypted values to persist.
        """
        df = pd.DataFrame({self.COLUMN_NAME: encrypted_values})
        df.to_csv(self.data_path, index=False)

    def load_values(self) -> List[float]:
        """
        Load all encrypted values from the storage CSV.

        Returns:
            List of floats (may be empty if no data has been stored yet).
        """
        try:
            df = pd.read_csv(self.data_path)
        except (FileNotFoundError, pd.errors.EmptyDataError):
            return []

        if self.COLUMN_NAME not in df.columns:
            return []

        return df[self.COLUMN_NAME].dropna().tolist()

    def clear(self) -> None:
        """Reset the storage CSV to an empty state."""
        self._init_csv()

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _init_csv(self) -> None:
        """Create an empty storage CSV with the correct header."""
        df = pd.DataFrame(columns=[self.COLUMN_NAME])
        df.to_csv(self.data_path, index=False)
