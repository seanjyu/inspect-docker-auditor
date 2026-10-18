import socket
from unittest.mock import MagicMock

import pytest

from inspect_docker_auditor.config import AuditorConfig
from inspect_docker_auditor.proxy_auditor import ProxyAuditor


@pytest.fixture
def sample_valid_yaml(tmp_path):
    """Creates a temporary YAML file with valid network_rules configurations."""
    yaml_content = """
network_rules:
  - name: allow_api
    enabled: true
    domains: ["api.example.com"]
  - name: block_admin
    enabled: true
    domains: ["admin.example.com"]
"""
    config_file = tmp_path / "valid_rules.yaml"
    config_file.write_text(yaml_content)
    return str(config_file)


@pytest.fixture
def sample_mixed_yaml(tmp_path):
    """Creates a temporary YAML file containing valid and invalid rule entries."""
    yaml_content = """
network_rules:
  - name: valid_rule
    enabled: true
    domains: ["valid.com"]
"""
    config_file = tmp_path / "mixed_rules.yaml"
    config_file.write_text(yaml_content)
    return str(config_file)


class TestAuditorInit:
    @pytest.mark.unit
    def test_init_loads_valid_configuration(self, sample_valid_yaml, monkeypatch):
        """
        Verify Auditor correctly loads config from CONFIG_PATH and parses valid rules.
        """
        monkeypatch.setenv("CONFIG_PATH", sample_valid_yaml)

        auditor = ProxyAuditor()

        assert auditor.config is not None
        assert isinstance(auditor.config, AuditorConfig)
        # Access network_rules via auditor.config
        assert len(auditor.config.network_rules) == 2
        assert auditor.config.network_rules[0].name == "allow_api"

    @pytest.mark.unit
    def test_init_missing_config_path_environment_variable(self, monkeypatch):
        """Verify default configuration initialization when CONFIG_PATH is missing."""
        monkeypatch.delenv("CONFIG_PATH", raising=False)

        auditor = ProxyAuditor()

        assert auditor.config is not None
        assert isinstance(auditor.config, AuditorConfig)

    @pytest.mark.unit
    def test_init_handles_invalid_rule_entries_gracefully(
        self, sample_mixed_yaml, monkeypatch
    ):
        """Verify rule entries are loaded into config correctly."""
        monkeypatch.setenv("CONFIG_PATH", sample_mixed_yaml)

        auditor = ProxyAuditor()

        assert auditor.config is not None
        assert len(auditor.config.network_rules) == 1
        assert auditor.config.network_rules[0].name == "valid_rule"

    @pytest.mark.unit
    def test_init_default_state_initialization(self, sample_valid_yaml, monkeypatch):
        """Verify internal auditor state initialization."""
        monkeypatch.setenv("CONFIG_PATH", sample_valid_yaml)
        # Ensure any mock target uses 'inspect_docker_auditor.proxy_auditor' full module
        # path
        auditor = ProxyAuditor()

        assert hasattr(auditor, "_ip_container_cache")
        assert auditor._ip_container_cache == {}


@pytest.fixture
def auditor_instance():
    """Provides a bare instance of the class containing _is_internal_host."""
    return ProxyAuditor()  # Replace with your actual class name


@pytest.mark.unit
class TestIsInternalHost:
    def test_direct_localhost_match(self, auditor_instance) -> None:
        """Tests hardcoded 'localhost' shortcuts without socket lookups."""
        is_internal, ip = auditor_instance._is_internal_host("localhost")
        assert is_internal is True
        assert ip == "127.0.0.1"

        is_internal_ld, ip_ld = auditor_instance._is_internal_host(
            "LOCALHOST.LOCALDOMAIN"
        )
        assert is_internal_ld is True
        assert ip_ld == "127.0.0.1"

    @pytest.mark.parametrize(
        "host,mocked_ip,expected_is_internal",
        [
            # Loopback IP
            ("127.0.0.1", "127.0.0.1", True),
            # Private RFC 1918 ranges
            ("10.0.0.1", "10.0.0.1", True),
            ("172.16.0.5", "172.16.0.5", True),
            ("192.168.1.100", "192.168.1.100", True),
            # Link-local / AWS & GCP Metadata endpoint
            ("169.254.169.254", "169.254.169.254", True),
            # Public IPs & Public domains
            ("8.8.8.8", "8.8.8.8", False),
            ("api.example.com", "93.184.216.34", False),
            # DNS Rebinding prevention (public domain resolving to private IP)
            ("evil-rebinding.com", "127.0.0.1", True),
            ("internal-attacker.com", "10.0.0.5", True),
        ],
    )
    def test_is_internal_host_ip_ranges(
        self,
        auditor_instance,
        monkeypatch: pytest.MonkeyPatch,
        host: str,
        mocked_ip: str,
        expected_is_internal: bool,
    ) -> None:
        """
        Verifies IP classification across private, public, link-local, and rebound
        addresses.
        """
        monkeypatch.setattr(socket, "gethostbyname", lambda _: mocked_ip)

        is_internal, resolved_ip = auditor_instance._is_internal_host(host)

        assert is_internal is expected_is_internal
        assert resolved_ip == mocked_ip

    def test_dns_resolution_failure_returns_unresolved(
        self, auditor_instance, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verifies that DNS failure inside the proxy returns (False, 'unresolved')."""

        def mock_dns_failure(h: str) -> str:
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "gethostbyname", mock_dns_failure)

        is_internal, resolved_ip = auditor_instance._is_internal_host(
            "unreachable.domain.invalid"
        )

        assert is_internal is False
        assert resolved_ip == "unresolved"


@pytest.mark.unit
class TestCheckEgressViolation:
    @pytest.fixture
    def mock_flow(self):
        """Creates a mock mitmproxy HTTPFlow object."""
        flow = MagicMock()
        flow.request.pretty_host = "example.com"
        return flow

    def test_internal_host_returns_violation_dict(
        self, auditor_instance, mock_flow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verifies that an internal host produces a 403 egress violation dictionary."""
        mock_flow.request.pretty_host = "internal-service.local"

        # Mock _is_internal_host to simulate detecting an internal host
        monkeypatch.setattr(
            auditor_instance,
            "_is_internal_host",
            lambda host: (True, "10.0.0.15"),
        )

        violation = auditor_instance._check_egress_violation(mock_flow)

        assert violation is not None
        assert isinstance(violation, dict)
        assert violation["rule_name"] == "System_Internal_Egress_Block"
        assert violation["status_code"] == 403
        assert "internal-service.local" in violation["message"][0]
        assert "10.0.0.15" in violation["message"][0]

    def test_external_host_returns_none(
        self, auditor_instance, mock_flow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verifies that external traffic returns None (no violation)."""
        mock_flow.request.pretty_host = "api.public.com"

        # Mock _is_internal_host to simulate an allowed public host
        monkeypatch.setattr(
            auditor_instance,
            "_is_internal_host",
            lambda host: (False, "93.184.216.34"),
        )

        violation = auditor_instance._check_egress_violation(mock_flow)

        assert violation is None

    def test_unresolved_host_returns_none(
        self, auditor_instance, mock_flow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Verifies that unresolvable domains pass egress checks without raising errors.
        """
        mock_flow.request.pretty_host = "unreachable.invalid"

        monkeypatch.setattr(
            auditor_instance,
            "_is_internal_host",
            lambda host: (False, "unresolved"),
        )

        violation = auditor_instance._check_egress_violation(mock_flow)

        assert violation is None
