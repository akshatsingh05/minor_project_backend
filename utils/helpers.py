"""
utils/helpers.py - General-Purpose Utility Functions

Provides lightweight helpers used across the backend:
    - Numeric validation
    - Safe JSON serialization
    - Rounding utilities
    - Response builder for consistent API responses
"""

import json
import math
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Numeric Validation
# ---------------------------------------------------------------------------

def is_numeric(value: Any) -> bool:
    """
    Return True if `value` can be safely interpreted as a finite float.

    Rejects:
        - None, empty strings, non-string/non-numeric types
        - Infinity and NaN
    """
    try:
        f = float(value)
        return math.isfinite(f)
    except (TypeError, ValueError):
        return False


def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Convert `value` to float; return `default` on failure.

    Args:
        value:   Input to convert.
        default: Fallback when conversion fails (default 0.0).
    """
    try:
        f = float(value)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def round_to(value: float, decimals: int = 4) -> float:
    """Round a float to `decimals` decimal places."""
    return round(value, decimals)


# ---------------------------------------------------------------------------
# Response Builders
# ---------------------------------------------------------------------------

def success_response(data: Dict[str, Any], message: str = "OK") -> Dict[str, Any]:
    """
    Wrap a data payload in a standard success envelope.

    Returns:
        {"status": "success", "message": ..., "data": ...}
    """
    return {
        "status": "success",
        "message": message,
        "data": data,
    }


def error_response(message: str, code: int = 400) -> Dict[str, Any]:
    """
    Wrap an error message in a standard error envelope.

    Returns:
        {"status": "error", "message": ..., "code": ...}
    """
    return {
        "status": "error",
        "message": message,
        "code": code,
    }


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def safe_json_dumps(obj: Any, indent: int = 2) -> str:
    """
    Serialize an object to JSON, converting non-serializable types gracefully.

    Handles:
        - float('nan') / float('inf') → None
        - Everything else via str()
    """

    def _default(o):
        if isinstance(o, float) and not math.isfinite(o):
            return None
        return str(o)

    return json.dumps(obj, indent=indent, default=_default)


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def clamp(value: float, lo: float, hi: float) -> float:
    """Clamp `value` to the range [lo, hi]."""
    return max(lo, min(hi, value))
