from unittest.mock import patch

import pytest

from libtea._security import _is_internal_ip, _validate_download_url, _validate_resolved_ips
from libtea.exceptions import TeaValidationError


class TestValidateDownloadUrl:
    def test_rejects_file_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("file:///etc/passwd")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("ftp://evil.com/file")

    def test_rejects_data_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("data:text/html,<h1>hi</h1>")

    def test_rejects_gopher_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("gopher://evil.com")

    def test_rejects_unknown_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("javascript:alert(1)")

    def test_rejects_missing_hostname(self):
        with pytest.raises(TeaValidationError, match="must include a hostname"):
            _validate_download_url("http:///path/only")

    def test_accepts_http(self):
        _validate_download_url("http://example.com/file.xml")

    def test_accepts_https(self):
        _validate_download_url("https://cdn.example.com/sbom.json")


class TestSsrfProtection:
    """Download URL must not target private/internal networks."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/file.xml",
            "http://10.0.0.1/file.xml",
            "http://172.16.0.1/file.xml",
            "http://192.168.1.1/file.xml",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/file.xml",
            "http://[::1]/file.xml",
            "http://localhost/file.xml",
            "http://localhost.localdomain/file.xml",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
    )
    def test_rejects_internal_urls(self, url):
        with pytest.raises(TeaValidationError):
            _validate_download_url(url)

    def test_rejects_cgnat_ip(self):
        """P0-1: CGNAT range (100.64.0.0/10) must be blocked."""
        with pytest.raises(TeaValidationError, match="private/internal"):
            _validate_download_url("http://100.64.0.1/file.xml")

    def test_accepts_public_url(self):
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            _validate_download_url("https://cdn.example.com/sbom.json")

    def test_accepts_public_ip(self):
        _validate_download_url("https://8.8.8.8/file.xml")

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/file.xml",
            "http://10.0.0.1/file.xml",
            "http://192.168.1.1/file.xml",
            "http://100.64.0.1/file.xml",
        ],
    )
    def test_allow_private_ips_bypasses_internal_checks(self, url):
        """allow_private_ips=True skips IP-based SSRF checks."""
        _validate_download_url(url, allow_private_ips=True)

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/file.xml",
            "https://metadata.google.internal/latest",
            "https://kubernetes.default.svc/api",
        ],
    )
    def test_allow_private_ips_still_rejects_blocked_hostnames(self, url):
        """Blocked hostnames (cloud metadata, k8s) are always enforced."""
        with pytest.raises(TeaValidationError, match="internal hosts"):
            _validate_download_url(url, allow_private_ips=True)

    def test_allow_private_ips_still_rejects_bad_scheme(self):
        """Scheme validation is always enforced, even with allow_private_ips."""
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("ftp://127.0.0.1/file.xml", allow_private_ips=True)

    def test_allow_private_ips_still_rejects_missing_hostname(self):
        with pytest.raises(TeaValidationError, match="must include a hostname"):
            _validate_download_url("http:///path/only", allow_private_ips=True)


class TestIsInternalIp:
    """Tests for the _is_internal_ip helper."""

    def test_cgnat_is_internal(self):
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv4Address("100.64.0.1"))
        assert _is_internal_ip(ipaddress.IPv4Address("100.127.255.254"))

    def test_public_ip_not_internal(self):
        import ipaddress

        assert not _is_internal_ip(ipaddress.IPv4Address("8.8.8.8"))
        assert not _is_internal_ip(ipaddress.IPv4Address("93.184.216.34"))

    def test_loopback_is_internal(self):
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv4Address("127.0.0.1"))

    def test_link_local_is_internal(self):
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv4Address("169.254.169.254"))

    def test_ipv6_loopback_is_internal(self):
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv6Address("::1"))

    def test_unspecified_is_internal(self):
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv4Address("0.0.0.0"))
        assert _is_internal_ip(ipaddress.IPv6Address("::"))

    def test_multicast_is_internal(self):
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv4Address("224.0.0.1"))
        assert _is_internal_ip(ipaddress.IPv6Address("ff02::1"))

    def test_ipv4_mapped_ipv6_cgnat_is_internal(self):
        """SEC-01: IPv4-mapped IPv6 CGNAT addresses must be blocked."""
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv6Address("::ffff:100.64.0.1"))
        assert _is_internal_ip(ipaddress.IPv6Address("::ffff:100.127.255.254"))

    def test_ipv4_mapped_ipv6_private_is_internal(self):
        import ipaddress

        assert _is_internal_ip(ipaddress.IPv6Address("::ffff:10.0.0.1"))
        assert _is_internal_ip(ipaddress.IPv6Address("::ffff:169.254.169.254"))

    def test_ipv4_mapped_ipv6_public_not_internal(self):
        import ipaddress

        assert not _is_internal_ip(ipaddress.IPv6Address("::ffff:8.8.8.8"))

    def test_skips_unparseable_sockaddr(self):
        """Non-IP address entries in getaddrinfo results are silently skipped."""
        fake_addr = [(1, 1, 0, "", ("/var/run/some.sock",))]
        with patch("libtea._security.socket.getaddrinfo", return_value=fake_addr):
            _validate_resolved_ips("unix-socket.example.com")  # should not raise


class TestDnsRebindingProtection:
    """DNS rebinding protection via hostname resolution check."""

    def test_rejects_hostname_resolving_to_loopback(self):
        fake_addr = [(2, 1, 6, "", ("127.0.0.1", 0))]
        with patch("libtea._security.socket.getaddrinfo", return_value=fake_addr):
            with pytest.raises(TeaValidationError, match="resolves to private/internal IP"):
                _validate_resolved_ips("evil-rebind.example.com")

    def test_rejects_hostname_resolving_to_private(self):
        fake_addr = [(2, 1, 6, "", ("10.0.0.1", 0))]
        with patch("libtea._security.socket.getaddrinfo", return_value=fake_addr):
            with pytest.raises(TeaValidationError, match="resolves to private/internal IP"):
                _validate_resolved_ips("evil-rebind.example.com")

    def test_rejects_hostname_resolving_to_link_local(self):
        fake_addr = [(2, 1, 6, "", ("169.254.169.254", 0))]
        with patch("libtea._security.socket.getaddrinfo", return_value=fake_addr):
            with pytest.raises(TeaValidationError, match="resolves to private/internal IP"):
                _validate_resolved_ips("evil-metadata.example.com")

    def test_accepts_hostname_resolving_to_public_ip(self):
        fake_addr = [(2, 1, 6, "", ("93.184.216.34", 0))]
        with patch("libtea._security.socket.getaddrinfo", return_value=fake_addr):
            _validate_resolved_ips("cdn.example.com")  # should not raise

    def test_rejects_hostname_resolving_to_cgnat(self):
        """P0-1: CGNAT range via DNS rebinding must be blocked."""
        fake_addr = [(2, 1, 6, "", ("100.64.0.1", 0))]
        with patch("libtea._security.socket.getaddrinfo", return_value=fake_addr):
            with pytest.raises(TeaValidationError, match="resolves to private/internal IP"):
                _validate_resolved_ips("evil-cgnat.example.com")

    def test_dns_failure_raises_validation_error(self):
        """DNS failure should raise TeaValidationError (fail-closed)."""
        import socket

        with patch("libtea._security.socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            with pytest.raises(TeaValidationError, match="DNS resolution failed"):
                _validate_resolved_ips("nonexistent.example.com")

    def test_validate_download_url_calls_dns_check(self):
        """Non-IP hostnames trigger DNS resolution check."""
        fake_addr = [(2, 1, 6, "", ("10.0.0.1", 0))]
        with patch("libtea._security.socket.getaddrinfo", return_value=fake_addr):
            with pytest.raises(TeaValidationError, match="resolves to private/internal IP"):
                _validate_download_url("https://evil-rebind.example.com/file.xml")
