import hashlib

import httpx
import pytest
import respx

from libtea.exceptions import TeaChecksumError
from libtea.models import Checksum, ChecksumAlgorithm

ARTIFACT_URL = "https://artifacts.example.com/sbom.json"
ARTIFACT_CONTENT = b'{"bomFormat": "CycloneDX", "specVersion": "1.5"}'


class TestDownloadArtifact:
    @respx.mock
    def test_download_without_checksum(self, client, tmp_path):
        respx.get(ARTIFACT_URL).mock(return_value=httpx.Response(200, content=ARTIFACT_CONTENT))
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest)
        assert result == dest
        assert dest.read_bytes() == ARTIFACT_CONTENT

    @respx.mock
    def test_download_with_valid_checksum(self, client, tmp_path):
        respx.get(ARTIFACT_URL).mock(return_value=httpx.Response(200, content=ARTIFACT_CONTENT))
        sha256 = hashlib.sha256(ARTIFACT_CONTENT).hexdigest()
        checksums = [Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value=sha256)]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest
        assert dest.exists()

    @respx.mock
    def test_download_with_invalid_checksum_deletes_file(self, client, tmp_path):
        respx.get(ARTIFACT_URL).mock(return_value=httpx.Response(200, content=ARTIFACT_CONTENT))
        checksums = [Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value="badhash")]
        dest = tmp_path / "sbom.json"
        with pytest.raises(TeaChecksumError, match="SHA-256"):
            client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert not dest.exists()

    @respx.mock
    def test_download_with_multiple_checksums(self, client, tmp_path):
        respx.get(ARTIFACT_URL).mock(return_value=httpx.Response(200, content=ARTIFACT_CONTENT))
        sha256 = hashlib.sha256(ARTIFACT_CONTENT).hexdigest()
        sha1 = hashlib.sha1(ARTIFACT_CONTENT).hexdigest()
        checksums = [
            Checksum(alg_type=ChecksumAlgorithm.SHA_1, alg_value=sha1),
            Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value=sha256),
        ]
        dest = tmp_path / "sbom.json"
        result = client.download_artifact(ARTIFACT_URL, dest, verify_checksums=checksums)
        assert result == dest

    @respx.mock
    def test_download_checksum_uppercase_hex_accepted(self, client, tmp_path):
        respx.get(ARTIFACT_URL).mock(return_value=httpx.Response(200, content=ARTIFACT_CONTENT))
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
