"""
modules/mpc_module.py - Simulated Multi-Party Computation (MPC) Module

Uses Additive Secret Sharing to split a secret value into N shares such that:
    share_1 + share_2 + ... + share_N = original_value

No single party can reconstruct the secret alone.  Only when all shares are
combined is the original value revealed — this is the core MPC security property.
"""

import random
from typing import List


class MPCEngine:
    """
    Simulates a 4-party MPC protocol via additive secret sharing.

    Splitting:
        Given secret S, generate (N-1) random values r_1 … r_(N-1).
        The final share is: r_N = S - (r_1 + r_2 + ... + r_(N-1)).
        This guarantees the shares sum to S.

    Reconstruction:
        Simply sum all N shares.
    """

    def __init__(self, num_parties: int = 4):
        """
        Args:
            num_parties: Number of parties / shares (default 4).
        """
        if num_parties < 2:
            raise ValueError("MPC requires at least 2 parties.")
        self.num_parties = num_parties

        # In-memory store: maps an encrypted value → its shares.
        # This simulates each party holding their own share locally.
        self._party_shares: dict = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def split(self, secret: float) -> List[float]:
        """
        Split a secret value into num_parties additive shares.

        Args:
            secret: The value to be shared (typically an encrypted value).

        Returns:
            A list of N float shares.
        """
        shares = self._generate_shares(secret)
        # Store shares keyed by the secret value for later reconstruction
        self._party_shares[secret] = shares
        return shares

    def reconstruct(self, secret: float) -> float:
        """
        Reconstruct the original secret from stored shares.

        Args:
            secret: The original value whose shares were stored via split().

        Returns:
            The reconstructed secret (should equal original within float precision).

        Raises:
            KeyError: If no shares exist for this secret.
        """
        if secret not in self._party_shares:
            raise KeyError(f"No shares found for value {secret}. Call split() first.")
        shares = self._party_shares[secret]
        return round(sum(shares), 6)

    def get_shares(self, secret: float) -> List[float]:
        """Return the raw shares for a given secret (for logging/debugging)."""
        return self._party_shares.get(secret, [])

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _generate_shares(self, secret: float) -> List[float]:
        """
        Create (num_parties - 1) random shares and derive the last share
        so that all shares sum exactly to `secret`.

        Random values are drawn from a reasonable range to keep shares
        realistic while preserving the additive property.
        """
        magnitude = abs(secret) + 1.0  # Avoid zero range
        random_shares = [
            random.uniform(-magnitude, magnitude)
            for _ in range(self.num_parties - 1)
        ]
        # Last share compensates so total = secret
        last_share = secret - sum(random_shares)
        shares = random_shares + [last_share]

        # Sanity check — sum of shares must equal the secret
        assert abs(sum(shares) - secret) < 1e-6, "Share generation failed invariant."
        return shares
