import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# Import functions and classes to test from environment.py
from inspect_docker_auditor.environment import (
    AuditedDockerSandboxEnvironment,
    AuditorPermissionError,
    ContainerTerminator,
    _extract_certs,
    _run_async,
    _wait_for_proxy_health,
    build_agent_environment,
    extract_sample_audit_telemetry,
)

# -----------------------------------------------------------------------------
# 1. Pure Helper Functions
# -----------------------------------------------------------------------------


def test_build_agent_environment():
    proxy_url = "http://sample_123@proxy:8080"
    container_cert_path = "/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"
    sample_id = "sample_123"
    no_proxy_str = "localhost,127.0.0.1"

    env = build_agent_environment(
        proxy_url=proxy_url,
        container_cert_path=container_cert_path,
        sample_id=sample_id,
        no_proxy_str=no_proxy_str,
    )

    assert env["HTTP_PROXY"] == proxy_url
    assert env["HTTPS_PROXY"] == proxy_url
    assert env["NO_PROXY"] == no_proxy_str
    assert env["REQUESTS_CA_BUNDLE"] == container_cert_path
    assert env["SSL_CERT_FILE"] == container_cert_path
    assert env["SAMPLE_ID"] == "sample_123"


def test_extract_sample_audit_telemetry_file_not_exists(tmp_path: Path):
    telemetry = extract_sample_audit_telemetry(tmp_path, "nonexistent_sample")

    assert telemetry["total_requests"] == 0
    assert telemetry["allowed_requests"] == 0
    assert telemetry["blocked_requests"] == 0
    assert telemetry["policy_violation"] is False


def test_extract_sample_audit_telemetry_valid(tmp_path: Path):
    sample_dir = tmp_path / "sample_123"
    sample_dir.mkdir(parents=True)
    audit_file = sample_dir / "audit_events.jsonl"

    events = [
        {"host": "api.example.com", "action": "ALLOW", "status_code": 200},
        {"host": "malicious.com", "action": "BLOCK", "status_code": 403},
        {"domain": "safe.org", "action": "ALLOW", "status_code": 200},
    ]

    audit_file.write_text("\n".join(json.dumps(e) for e in events))

    telemetry = extract_sample_audit_telemetry(tmp_path, "123")

    assert telemetry["total_requests"] == 3
    assert telemetry["allowed_requests"] == 2
    assert telemetry["blocked_requests"] == 1
    assert telemetry["policy_violation"] is True
    assert "malicious.com" in telemetry["blocked_domains"]
    assert "api.example.com" in telemetry["domains_accessed"]


# -----------------------------------------------------------------------------
# 2. ContainerTerminator
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_container_terminator_success():
    terminator = ContainerTerminator()

    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"", b"")
    mock_proc.returncode = 0

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        result = await terminator.terminate("test_container", "Policy violation")

        assert result is True
        mock_exec.assert_called_once_with(
            "docker",
            "kill",
            "test_container",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )


@pytest.mark.asyncio
async def test_container_terminator_failure():
    terminator = ContainerTerminator()

    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"", b"No such container")
    mock_proc.returncode = 1

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await terminator.terminate("nonexistent_container", "Test kill")
        assert result is False


# -----------------------------------------------------------------------------
# 3. Shell & Async Helpers (_run_async, _stream_container_logs_to_file, etc.)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_async_success():
    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"output", b"")
    mock_proc.returncode = 0

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        stdout, stderr = await _run_async("echo", "hello", check=True)
        assert stdout == b"output"
        assert stderr == b""


@pytest.mark.asyncio
async def test_run_async_failure_raises_runtime_error():
    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"", b"Command not found")
    mock_proc.returncode = 1

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with pytest.raises(RuntimeError, match="Command failed"):
            await _run_async("false", check=True)


@pytest.mark.asyncio
async def test_wait_for_proxy_health_success():
    mock_proc = AsyncMock()
    mock_proc.wait.return_value = 0
    mock_proc.returncode = 0

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        # Should complete without raising an exception
        await _wait_for_proxy_health(
            proxy_name="proxy_container", proxy_port=8080, timeout=2
        )


@pytest.mark.asyncio
async def test_wait_for_proxy_health_timeout():
    # Use standard library patch context manager instead of the mocker fixture
    with patch(
        "httpx.AsyncClient.get", side_effect=httpx.ConnectError("Connection refused")
    ):
        with pytest.raises(RuntimeError):
            await _wait_for_proxy_health(
                proxy_name="test_proxy", proxy_port=8080, timeout=0.1
            )


@pytest.mark.asyncio
async def test_extract_certs_already_exists(tmp_path: Path):
    host_cert = tmp_path / "mitmproxy-ca-cert.pem"
    host_cert.write_text("existing cert content")

    with patch("asyncio.create_subprocess_exec") as mock_exec:
        await _extract_certs("proxy_container", tmp_path)
        mock_exec.assert_not_called()


@pytest.mark.unit
def test_audited_sandbox_config_deserialize():
    # String-patch DockerSandboxEnvironment where environment.py imports it
    with patch(
        "inspect_docker_auditor.environment.DockerSandboxEnvironment.__init__",
        return_value=None,
    ):
        # 1. Existing instance pass-through
        existing_env = AuditedDockerSandboxEnvironment()
        assert (
            AuditedDockerSandboxEnvironment.config_deserialize(existing_env)
            is existing_env
        )

        # 2. Dict input unpacking
        env_from_dict = AuditedDockerSandboxEnvironment.config_deserialize(
            {"service": "default"}
        )
        assert isinstance(env_from_dict, AuditedDockerSandboxEnvironment)

        # 3. String path input
        env_from_str = AuditedDockerSandboxEnvironment.config_deserialize("config.yaml")
        assert isinstance(env_from_str, AuditedDockerSandboxEnvironment)
        # assert env_from_str.config == "config.yaml"

        # 4. Direct kwargs input
        env_from_kwargs = AuditedDockerSandboxEnvironment.config_deserialize(
            service="default"
        )
        assert isinstance(env_from_kwargs, AuditedDockerSandboxEnvironment)

        # 5. Default / No args
        env_default = AuditedDockerSandboxEnvironment.config_deserialize()
        assert isinstance(env_default, AuditedDockerSandboxEnvironment)


def test_audited_sandbox_mark_policy_violation():
    # env = AuditedDockerSandboxEnvironment()
    env = AuditedDockerSandboxEnvironment(
        service="default", project="test-project", working_dir="/workspace"
    )

    mock_task = MagicMock(spec=asyncio.Task)
    mock_task.done.return_value = False
    env._active_exec_tasks.add(mock_task)

    env.mark_policy_violation("Blocked IP access")

    assert env._network_violation == "Blocked IP access"
    mock_task.cancel.assert_called_once()


def test_audited_sandbox_raise_if_network_violation():
    # env = AuditedDockerSandboxEnvironment()
    env = AuditedDockerSandboxEnvironment(
        service="default", project="test-project", working_dir="/workspace"
    )

    # No violation set -> should not raise
    env._raise_if_network_violation()

    # Violation set -> should raise AuditorPermissionError
    env._network_violation = "Unauthorized outbound host"
    with pytest.raises(AuditorPermissionError) as exc_info:
        env._raise_if_network_violation()

    assert "Unauthorized outbound host" in str(exc_info.value)


# TODO move terminate for policy checks to integration because it requires a sample to
# be initiated
# @pytest.mark.asyncio
# async def test_audited_sandbox_terminate_for_policy():
#     # env = AuditedDockerSandboxEnvironment()

#     env = AuditedDockerSandboxEnvironment(
#         service="default",
#         project="test-project",
#         working_dir="/workspace"
#     )

#     env.terminator = AsyncMock(spec=ContainerTerminator)

#     await env.terminate_for_policy("Dangerous domain requested", "container_abc")

#     assert env._network_violation == "Dangerous domain requested"
#     env.terminator.terminate.assert_called_once_with(
#         container_id="container_abc",
#         reason="[POLICY VIOLATION] Dangerous domain requested"
#     )


@pytest.mark.asyncio
async def test_audited_sandbox_exec_command_rule_violation():
    # env = AuditedDockerSandboxEnvironment()
    env = AuditedDockerSandboxEnvironment(
        service="default", project="test-project", working_dir="/workspace"
    )
    env.resolved_id = "sample_test"

    # Mock AuditorConfig with command rule violations
    mock_rule = MagicMock()
    mock_rule.pattern = r"rm -rf /"
    mock_rule.name = "NO_DESTRUCTIVE_RM"
    mock_rule.message = "Deletion of root is forbidden"

    mock_config = MagicMock()
    mock_config.command_rules = [mock_rule]
    mock_config.terminate_on_violation = False
    env.auditor_config = mock_config

    with pytest.raises(AuditorPermissionError, match="Command blocked by policy"):
        await env.exec(["rm", "-rf", "/"])

    assert env.network_violation is not None
