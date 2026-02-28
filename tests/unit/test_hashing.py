import hashlib

import pytest
import responses

from libtea._hashing import _build_hashers
from libtea._http import TeaHttpClient
from libtea.exceptions import TeaChecksumError


class TestBuildHashers:
    def test_blake3_raises(self):
        with pytest.raises(TeaChecksumError, match="BLAKE3"):
            _build_hashers(["BLAKE3"])

    def test_unknown_algorithm_raises(self):
        with pytest.raises(TeaChecksumError, match="Unsupported checksum algorithm"):
            _build_hashers(["UNKNOWN-ALG"])

    @pytest.mark.parametrize(
        "algorithm",
        ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"],
    )
    def test_standard_algorithms(self, algorithm):
        hashers = _build_hashers([algorithm])
        assert algorithm in hashers
        # Verify the hasher produces a hex digest
        hashers[algorithm].update(b"test")
        assert len(hashers[algorithm].hexdigest()) > 0

    @pytest.mark.parametrize("algorithm,digest_size", [("BLAKE2b-256", 32), ("BLAKE2b-384", 48), ("BLAKE2b-512", 64)])
    def test_blake2b_variants(self, algorithm, digest_size):
        hashers = _build_hashers([algorithm])
        assert algorithm in hashers
        hashers[algorithm].update(b"test")
        # BLAKE2b hex digest length = digest_size * 2
        assert len(hashers[algorithm].hexdigest()) == digest_size * 2

    @responses.activate
    def test_all_algorithms_produce_correct_digests(self, tmp_path):
        """End-to-end: download with each algorithm and verify the digest is correct."""
        content = b"algorithm test content"
        url = "https://artifacts.example.com/test.bin"
        responses.get(url, body=content)

        client = TeaHttpClient(base_url="https://api.example.com")
        all_algs = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"]

        dest = tmp_path / "test.bin"
        digests = client.download_with_hashes(url=url, dest=dest, algorithms=all_algs)
        client.close()

        assert digests["MD5"] == hashlib.md5(content).hexdigest()
        assert digests["SHA-1"] == hashlib.sha1(content).hexdigest()
        assert digests["SHA-256"] == hashlib.sha256(content).hexdigest()
        assert digests["SHA-384"] == hashlib.sha384(content).hexdigest()
        assert digests["SHA-512"] == hashlib.sha512(content).hexdigest()
        assert digests["SHA3-256"] == hashlib.new("sha3_256", content).hexdigest()
        assert digests["SHA3-384"] == hashlib.new("sha3_384", content).hexdigest()
        assert digests["SHA3-512"] == hashlib.new("sha3_512", content).hexdigest()
