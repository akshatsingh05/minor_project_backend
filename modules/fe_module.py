"""
modules/fe_module.py - Simplified Functional Encryption (FE) Module

Prototype implementation of Functional Encryption using a linear function:
    encrypt: y = k * x      (multiply by secret key)
    decrypt: x = y / k      (divide by secret key)

Key is held ONLY in memory — never persisted to disk.
"""


class FunctionalEncryption:
    """
    Simulates Functional Encryption with a linear transformation y = k*x.

    In a real FE system the key would be a secret master key that allows
    computing specific functions over ciphertexts.  Here we model the core
    idea: data is transformed by the key before storage and can only be
    recovered (decrypted) by someone possessing the key.
    """

    def __init__(self, key: float = 7):
        """
        Initialize FE with an in-memory secret key.

        Args:
            key: The scalar multiplier used for encryption (default 7).
                 This value is NEVER written to disk.
        """
        if key == 0:
            raise ValueError("Encryption key must not be zero.")
        self._key = key  # Private — not exposed outside this class

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt(self, value: float) -> float:
        """
        Encrypt a plaintext value using the linear function y = k * x.

        Args:
            value: Numeric plaintext value.

        Returns:
            Encrypted (transformed) numeric value.
        """
        return round(self._key * value, 6)

    def decrypt(self, encrypted_value: float) -> float:
        """
        Recover the original value from an encrypted value: x = y / k.

        Args:
            encrypted_value: The value previously produced by encrypt().

        Returns:
            Original plaintext numeric value.
        """
        return round(encrypted_value / self._key, 6)

    def get_key_fingerprint(self) -> str:
        """
        Return a non-reversible fingerprint (hash) of the key for audit
        purposes, without exposing the key itself.
        """
        import hashlib
        raw = str(self._key).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]
