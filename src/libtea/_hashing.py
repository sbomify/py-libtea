"""Checksum hash builder for TEA artifact verification.

Maps TEA algorithm names to ``hashlib`` hash objects. Used by
:meth:`~libtea._http.TeaHttpClient.download_with_hashes` to compute
digests on-the-fly during streaming downloads.
"""

import hashlib
from typing import Any

from libtea.exceptions import TeaChecksumError

# Hash algorithm registry: {TEA name: (hashlib name, digest_size)}.
# When digest_size is None, hashlib.new(name) is used with its default size.
# When digest_size is set, hashlib.blake2b(digest_size=N) is used instead.
# BLAKE3 is intentionally excluded — handled separately in _build_hashers.
_HASH_REGISTRY: dict[str, tuple[str, int | None]] = {
    "MD5": ("md5", None),
    "SHA-1": ("sha1", None),
    "SHA-256": ("sha256", None),
    "SHA-384": ("sha384", None),
    "SHA-512": ("sha512", None),
    "SHA3-256": ("sha3_256", None),
    "SHA3-384": ("sha3_384", None),
    "SHA3-512": ("sha3_512", None),
    "BLAKE2b-256": ("blake2b", 32),
    "BLAKE2b-384": ("blake2b", 48),
    "BLAKE2b-512": ("blake2b", 64),
}


def _build_hashers(algorithms: list[str]) -> dict[str, Any]:
    """Build ``hashlib`` hasher objects for the given TEA algorithm names.

    Args:
        algorithms: List of TEA checksum algorithm names (e.g. ``["SHA-256", "BLAKE2b-256"]``).

    Returns:
        Dict mapping algorithm name to a fresh hashlib hash object.

    Raises:
        TeaChecksumError: If BLAKE3 is requested (not in stdlib) or the algorithm is unknown.
    """
    hashers: dict[str, Any] = {}
    for alg in algorithms:
        if alg == "BLAKE3":
            raise TeaChecksumError(
                "BLAKE3 is not supported by Python's hashlib. "
                "Install the 'blake3' package or use a different algorithm.",
                algorithm="BLAKE3",
            )
        entry = _HASH_REGISTRY.get(alg)
        if entry is None:
            raise TeaChecksumError(
                f"Unsupported checksum algorithm: {alg!r}. Supported: {', '.join(sorted(_HASH_REGISTRY.keys()))}",
                algorithm=alg,
            )
        hashlib_name, digest_size = entry
        if digest_size is not None:
            hashers[alg] = hashlib.blake2b(digest_size=digest_size)
        else:
            hashers[alg] = hashlib.new(hashlib_name)
    return hashers
