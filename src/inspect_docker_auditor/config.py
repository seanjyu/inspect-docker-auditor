import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class CommandRuleConfig(BaseModel):
    """Config for auditing bash commands"""

    name: str
    pattern: str
    action: Literal["BLOCK", "ALLOW", "WARN"] = "BLOCK"
    message: str = "Command execution prohibited by policy"

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        """Ensures the regex pattern compiles at load time."""
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{v}': {e}") from e
        return v


class NetworkRuleConfig(BaseModel):
    name: str
    enabled: bool = True
    domains: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    action: Literal["BLOCK", "ALLOW", "WARN"] = "BLOCK"
    status_code: int = 403
    message: str = "Request blocked by security policy"


class AuditorConfig(BaseModel):
    # mitm configs
    sample_id_field: str | None = None

    shared_network_name: str = Field(default="", validation_alias="shared_network_name")
    proxy_name: str = Field(default="", validation_alias="proxy_name")
    proxy_port: int = Field(default=8080, validation_alias="proxy_port")
    socket_proxy_name: str = Field(default="", validation_alias="socket_proxy_name")
    socket_proxy_port: int = Field(default=2375, validation_alias="socket_proxy_port")
    setup_verbose: bool = Field(default=True, validation_alias="setup_verbose")
    proxy_health_check: bool = Field(
        default=True, validation_alias="proxy_health_check"
    )
    proxy_health_check_verbose: bool = Field(
        default=True, validation_alias="proxy_health_check_verbose"
    )

    log_dir: str = Field(default="logs", validation_alias="log_dir")
    save_docker_logs: bool = Field(default=True, validation_alias="save_docker_logs")

    # proxy configs
    terminate_on_violation: bool = Field(
        default=False, validation_alias="terminate_on_violation"
    )
    cache_ttl: int = Field(default=30, validation_alias="cache_ttl")
    save_mitmproxy_logs: bool = Field(
        default=True, validation_alias="save_mitmproxy_logs"
    )

    # network rules
    network_rules: list[NetworkRuleConfig] = Field(
        default_factory=list, validation_alias="network_rules"
    )

    # bypass rules
    bypass: list[str] = Field(default=[], validation_alias="bypass")

    # Command Execution Rules
    command_rules: list[CommandRuleConfig] = Field(
        default_factory=list, validation_alias="command_rules"
    )

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> "AuditorConfig":
        """
        Loads and parses an AuditorConfig from a YAML file path.

        - If path is None, reads from CONFIG_PATH environment variable.
        - If no path is provided and CONFIG_PATH is unset, returns default
          AuditorConfig().
        - Raises FileNotFoundError if an explicit or configured path does not exist.
        """
        if path is None:
            path = os.getenv("CONFIG_PATH")

        # No path given and CONFIG_PATH is unset -> return defaults safely
        if not path:
            return cls()

        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")

        try:
            with open(file_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            print(f"[ProxyAuditor] Successfully loaded config from {file_path}")
            return cls(**data)
        except Exception as e:
            print(
                f"[ProxyAuditor] Failed to parse config at {file_path}: {e}. Using "
                "defaults."
            )
            return cls()

    @field_validator("bypass", mode="before")
    @classmethod
    def validate_and_clean_bypass(cls, value: list[str]) -> list[str]:
        """
        Validates entries, strips protocols, removes whitespace,
        and eliminates duplicates while preserving order.
        """
        if not isinstance(value, list):
            raise ValueError("bypass configuration must be a list of strings")

        cleaned_targets: list[str] = []
        for raw in value:
            if not isinstance(raw, str):
                raise ValueError(f"Invalid bypass target '{raw}': must be a string")

            target = raw.strip()
            if not target:
                continue

            # Strip protocol prefixes if accidentally supplied
            # (e.g. "http://localhost:8080" -> "localhost:8080")
            target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)

            # Reject full paths or path separators
            if "/" in target:
                raise ValueError(
                    f"Invalid bypass target '{raw}': host entries cannot include URL "
                    "paths or trailing slashes"
                )

            cleaned_targets.append(target)

        # Deduplicate while preserving original order
        return list(dict.fromkeys(cleaned_targets))

    @property
    def bypass_regex(self) -> str:
        """Converts the bypass list into a regex string for mitmproxy --ignore-hosts."""
        if not self.bypass:
            return "$^"  # Matches nothing if list is empty

        patterns: list[str] = []
        for target in self.bypass:
            escaped = re.escape(target).replace(r"\*", ".*")
            if ":" in target:
                # Target has an explicit port (e.g., "172.17.0.1:8080")
                patterns.append(f"^{escaped}$")
            else:
                # Host/IP only -> matches domain with any port or no port
                patterns.append(f"^{escaped}(:|\\b|$)")

        return "|".join(patterns)

    @property
    def no_proxy_str(self) -> str:
        """Converts the bypass list into a comma-separated string for NO_PROXY."""
        return ",".join(self.bypass)
