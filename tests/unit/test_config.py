# tests/unit/test_config.py
from pathlib import Path

import pytest
from pydantic import ValidationError

from inspect_docker_auditor.config import AuditorConfig, CommandRuleConfig


@pytest.mark.unit
def test_load_auditor_config_from_yaml(sample_config_yaml: Path) -> None:
    """Verify loading AuditorConfig from a valid YAML file."""
    config = AuditorConfig.from_yaml(sample_config_yaml)

    assert config.proxy_name == "test_mitmproxy"
    assert config.proxy_port == 8080
    assert config.save_docker_logs is True

    # Network rules
    assert len(config.network_rules) == 1
    assert config.network_rules[0].name == "block_blacklist"
    assert config.network_rules[0].domains == ["example.com", "*.badsite.org"]
    assert config.network_rules[0].action == "BLOCK"

    # Command rules
    assert len(config.command_rules) == 1
    assert config.command_rules[0].name == "block_cat_passwd"

    # Bypass protocol cleaning
    assert "api.openai.com" in config.bypass
    assert "http://api.openai.com" not in config.bypass


@pytest.mark.unit
def test_default_config_fallback() -> None:
    """Verify default values when instantiated without arguments."""
    config = AuditorConfig()

    assert config.save_docker_logs is True
    assert config.proxy_port == 8080
    assert config.socket_proxy_port == 2375
    assert config.terminate_on_violation is False
    assert config.network_rules == []
    assert config.command_rules == []
    assert config.bypass == []


@pytest.mark.unit
def test_from_yaml_valid_file(tmp_path: Path) -> None:
    """Verify that from_yaml correctly parses a valid YAML file."""
    yaml_file = tmp_path / "valid.yaml"
    yaml_file.write_text(
        "network_rules: [{name: 'rule1', enabled: true, domains: ['test.com']}]"
    )

    config = AuditorConfig.from_yaml(yaml_file)

    assert len(config.network_rules) == 1
    assert config.network_rules[0].name == "rule1"


@pytest.mark.unit
def test_from_yaml_file_not_found(tmp_path: Path) -> None:
    """Verify that from_yaml raises FileNotFoundError if file does not exist."""
    non_existent = tmp_path / "does_not_exist.yaml"
    with pytest.raises(FileNotFoundError):
        AuditorConfig.from_yaml(non_existent)


@pytest.mark.unit
def test_from_yaml_default_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that calling from_yaml() with no path and no CONFIG_PATH env var returns
    empty defaults.
    """
    monkeypatch.delenv("CONFIG_PATH", raising=False)

    config = AuditorConfig.from_yaml(None)

    # Asserts that config matches the unpopulated default instance
    assert isinstance(config, AuditorConfig)
    assert config == AuditorConfig()
    assert config.network_rules == []
    assert config.command_rules == []


@pytest.mark.unit
def test_bypass_validation_and_cleaning() -> None:
    """
    Test protocol stripping, deduplication, and invalid path rejection in bypass list.
    """
    raw_bypass = [
        "https://api.openai.com",
        "api.openai.com",  # Duplicate after cleaning
        "  172.17.0.1  ",  # Whitespace
        "localhost:8080",
    ]
    config = AuditorConfig(bypass=raw_bypass)

    assert config.bypass == ["api.openai.com", "172.17.0.1", "localhost:8080"]


@pytest.mark.unit
def test_bypass_validation_rejects_paths() -> None:
    """Verify that URL paths inside bypass entries raise a ValidationError."""
    with pytest.raises(ValidationError, match="cannot include URL paths"):
        AuditorConfig(bypass=["api.openai.com/v1/chat"])


@pytest.mark.unit
def test_bypass_properties() -> None:
    """Test no_proxy_str and bypass_regex output generation."""
    config = AuditorConfig(bypass=["api.openai.com", "172.17.0.1:8080", "*.github.com"])

    # NO_PROXY string
    assert config.no_proxy_str == "api.openai.com,172.17.0.1:8080,*.github.com"

    # mitmproxy ignore-hosts regex
    regex = config.bypass_regex
    assert "^api\\.openai\\.com(:|\\b|$)" in regex
    assert "^172\\.17\\.0\\.1:8080$" in regex
    assert "^.*\\.github\\.com(:|\\b|$)" in regex


@pytest.mark.unit
def test_empty_bypass_regex() -> None:
    """Verify empty bypass list produces a regex that matches nothing."""
    config = AuditorConfig(bypass=[])
    assert config.bypass_regex == "$^"


@pytest.mark.unit
def test_command_rule_regex_validation() -> None:
    """Test that invalid regex patterns in command rules fail at model validation."""
    with pytest.raises(ValidationError, match="Invalid regex pattern"):
        CommandRuleConfig(name="invalid_rule", pattern="[unclosed_bracket")
