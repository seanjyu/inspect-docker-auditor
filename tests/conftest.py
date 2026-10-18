import os
import tempfile
from pathlib import Path

import pytest

# Create a temporary default config file for import time
_temp_dir = tempfile.TemporaryDirectory()
_default_config = Path(_temp_dir.name) / "default_config.yaml"
_default_config.write_text("""
rules: []
""")

# Set environment variable BEFORE any tests or modules are imported
os.environ["CONFIG_PATH"] = str(_default_config)

# @pytest.fixture
# def sample_config_yaml(tmp_path: Path) -> Path:
#     """Creates a temporary valid YAML config file matching AuditorConfig schema."""
#     config_file = tmp_path / "test_config.yaml"
#     config_file.write_text("""
# proxy_name: "test_mitmproxy"
# proxy_port: 8080
# save_docker_logs: true
# terminate_on_violation: false
# network_name: "inspect_audit_net"

# network_rules:
#   - name: "block_blacklist"
#     domains:
#       - "example.com"
#       - "*.badsite.org"
#     action: "BLOCK"
#     status_code: 403

# bypass:
#   - "http://api.openai.com"
#   - "api.anthropic.com"
#   - "host.docker.internal:8000"

# command_rules:
#   - name: "block_cat_passwd"
#     pattern: "cat\\\\s+/etc/passwd"
#     action: "BLOCK"
# """)
#     return config_file


@pytest.fixture
def sample_config_yaml(tmp_path: Path) -> Path:
    """Creates a temporary valid YAML config file matching AuditorConfig schema."""
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(r"""
proxy_name: "test_mitmproxy"
proxy_port: 8080
shared_network_name: "auditor"
socket_proxy_name: "socket_proxy"
save_docker_logs: true
socket_proxy_port: 2375
terminate_on_violation: false
network_name: "inspect_audit_net"
setup_verbose: True

sample_id_field: "test_custom_id"
log_dir: "./audit_logs"
save_docker_logs: True

proxy_check_health: False
proxy_check_health_verbose: False
cache_ttl: 30
save_mitmproxy_logs: False


network_rules:
  - name: "block_blacklist"
    domains:
      - "https://www.some_evil_website.com"
      - "*.badsite.org"
    action: "BLOCK"
    status_code: 403

bypass:
  - "http://api.openai.com"
  - "api.anthropic.com"
  - "host.docker.internal:8000"

command_rules:
  - name: "block_cat_passwd"
    pattern: "cat\\s+/etc/passwd"
    action: "BLOCK"
""")
    return config_file


@pytest.fixture
def sample_terminate_on_violation_config_yaml(tmp_path: Path) -> Path:
    """Creates a temporary valid YAML config file matching
    AuditorConfig schema with on violation block set to True"""
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(r"""
proxy_name: "test_mitmproxy"
proxy_port: 8080
shared_network_name: "auditor"
socket_proxy_name: "socket_proxy"
save_docker_logs: true
socket_proxy_port: 2375
terminate_on_violation: True
network_name: "inspect_audit_net"
setup_verbose: True

sample_id_field: "test_custom_id"
log_dir: "./audit_logs"
save_docker_logs: True

proxy_check_health: False
proxy_check_health_verbose: False
cache_ttl: 30
save_mitmproxy_logs: False


network_rules:
  - name: "block_blacklist"
    domains:
      - "example.com"
      - "*.badsite.org"
    action: "BLOCK"
    status_code: 403

bypass:
  - "http://api.openai.com"
  - "api.anthropic.com"
  - "host.docker.internal:8000"

command_rules:
  - name: "block_cat_passwd"
    pattern: "cat\\s+/etc/passwd"
    action: "BLOCK"
""")
    return config_file


# @pytest.fixture
# def mock_sandbox_env() -> MagicMock:
#     """Creates a mocked Inspect AI SandboxEnvironment for unit testing."""
#     env = MagicMock()
#     env.name = "default"
#     env.container_id = "mock_container_123"
#     env.resolved_id = "sample_test_001"

#     # Mock exec() method to return a successful ExecResult
#     mock_exec_result = MagicMock()
#     mock_exec_result.returncode = 0
#     mock_exec_result.stdout = "mock_output\n"
#     mock_exec_result.stderr = ""
#     env.exec = AsyncMock(return_value=mock_exec_result)

#     return env
