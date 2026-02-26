import hashlib

import pytest
import responses

from libtea.exceptions import TeaChecksumError
from libtea.models import Checksum, ChecksumAlgorithm

ARTIFACT_URL = "https://artifacts.example.com/sbom.json"
ARTIFACT_CONTENT = b'{"bomFormat": "CycloneDX", "specVersion": "1.5"}'


class TestDownloadArtifact:
    @responses.activate
    def test_download_without_checksum(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest)
        assert result == dest
        assert dest.read_bytes() == ARTIFACT_CONTENT

    @responses.activate
    def test_download_with_valid_checksum(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        sha256 = hashlib.sha256(ARTIFACT_CONTENT).hexdigest()
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value=sha256)]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest
        assert dest.exists()

    @responses.activate
    def test_download_with_invalid_checksum_deletes_file(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="badhash")]
        dest = tmp_path / "sbom.json"
        with pytest.raises(TeaChecksumError, match="SHA-256") as exc_info:
            client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert not dest.exists()
        assert exc_info.value.algorithm == "SHA-256"
        assert exc_info.value.expected == "badhash"
        assert exc_info.value.actual is not None

    @responses.activate
    def test_download_with_multiple_checksums(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        sha256 = hashlib.sha256(ARTIFACT_CONTENT).hexdigest()
        sha1 = hashlib.sha1(ARTIFACT_CONTENT).hexdigest()
        checksums = [
            Checksum(algorithm_type=ChecksumAlgorithm.SHA_1, algorithm_value=sha1),
            Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value=sha256),
        ]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest

    @responses.activate
    def test_download_checksum_uppercase_hex_accepted(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        sha256 = hashlib.sha256(ARTIFACT_CONTENT).hexdigest().upper()
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value=sha256)]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest

    def test_download_with_blake3_raises_clear_error(self, client, tmp_path):
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.BLAKE3, algorithm_value="somevalue")]
        dest = tmp_path / "sbom.json"
        with pytest.raises(TeaChecksumError, match="BLAKE3") as exc_info:
            client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert exc_info.value.algorithm == "BLAKE3"

    def test_download_with_unknown_algorithm_raises_clear_error(self, client, tmp_path):
        """If an algorithm has no hashlib mapping, verification should raise explicitly."""
        from unittest.mock import patch

        dest = tmp_path / "sbom.json"
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abc123")]
        with patch.object(client._http, "download_with_hashes", return_value={}):
            with pytest.raises(TeaChecksumError, match="No computed digest") as exc_info:
                client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
            assert not dest.exists()
            assert exc_info.value.algorithm == "SHA-256"

    @responses.activate
    def test_download_zero_byte_artifact(self, client, tmp_path):
        """Zero-byte artifacts are valid (e.g. stub SBOMs)."""
        responses.get(ARTIFACT_URL, body=b"")
        sha256 = hashlib.sha256(b"").hexdigest()
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value=sha256)]
        dest = tmp_path / "empty.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest
        assert dest.read_bytes() == b""

    @responses.activate
    def test_download_multi_chunk_artifact(self, client, tmp_path):
        """Content > 8192 bytes exercises multi-chunk hashing."""
        content = b"A" * 20000
        responses.get(ARTIFACT_URL, body=content)
        sha256 = hashlib.sha256(content).hexdigest()
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value=sha256)]
        dest = tmp_path / "large.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest
        assert dest.read_bytes() == content
