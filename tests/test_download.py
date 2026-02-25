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
        checksums = [Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value=sha256)]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest
        assert dest.exists()

    @responses.activate
    def test_download_with_invalid_checksum_deletes_file(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        checksums = [Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value="badhash")]
        dest = tmp_path / "sbom.json"
        with pytest.raises(TeaChecksumError, match="SHA-256"):
            client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert not dest.exists()

    @responses.activate
    def test_download_with_multiple_checksums(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        sha256 = hashlib.sha256(ARTIFACT_CONTENT).hexdigest()
        sha1 = hashlib.sha1(ARTIFACT_CONTENT).hexdigest()
        checksums = [
            Checksum(alg_type=ChecksumAlgorithm.SHA_1, alg_value=sha1),
            Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value=sha256),
        ]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest

    @responses.activate
    def test_download_checksum_uppercase_hex_accepted(self, client, tmp_path):
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        sha256 = hashlib.sha256(ARTIFACT_CONTENT).hexdigest().upper()
        checksums = [Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value=sha256)]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest

    def test_download_with_blake3_raises_clear_error(self, client, tmp_path):
        checksums = [Checksum(alg_type=ChecksumAlgorithm.BLAKE3, alg_value="somevalue")]
        dest = tmp_path / "sbom.json"
        with pytest.raises(TeaChecksumError, match="BLAKE3"):
            client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)

    @responses.activate
    def test_download_with_unknown_algorithm_raises_clear_error(self, client, tmp_path):
        """If an algorithm has no hashlib mapping, verification should raise explicitly."""
        responses.get(ARTIFACT_URL, body=ARTIFACT_CONTENT)
        checksums = [Checksum(alg_type=ChecksumAlgorithm.BLAKE3, alg_value="abc123")]
        dest = tmp_path / "sbom.json"
        from unittest.mock import patch

        # Patch download_with_hashes to return empty dict (no algorithms computed)
        with patch.object(client._http, "download_with_hashes", return_value={}):
            checksums = [Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value="abc123")]
            with pytest.raises(TeaChecksumError, match="No computed digest"):
                client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
            assert not dest.exists()
