import asyncio
import json
import os
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict, cast

from inspect_ai.util import (
    ComposeBuild,
    ComposeConfig,
    ComposeService,
    ExecResult,
    SandboxEnvironment,
    sandboxenv,
)
from inspect_ai.util._sandbox.docker.docker import DockerSandboxEnvironment

from inspect_docker_auditor.config import AuditorConfig

from .exceptions import AuditorPermissionError

# Global variables
PACKAGE_DIR = Path(__file__).parent.resolve()
ROOT_DIR = PACKAGE_DIR.parent.parent
CERTS_DIR_NAME = "certs"
CERTS_DIR = ROOT_DIR / CERTS_DIR_NAME
CERTS_DIR.mkdir(parents=True, exist_ok=True)
CONTAINER_CERT_PATH = "/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"

_init_lock = asyncio.Lock()
_socket_server: asyncio.Server | None = None
_proxy_started: bool = False
_infra_log_tasks: list[asyncio.Task] = []


class ContainerTerminator:
    def __init__(self, docker_host: str | None = None):
        # TODO add verbose object?
        self.docker_host = docker_host

    async def terminate(self, container_id: str, reason: str) -> bool:
        """
        Kills the specified container instance immediately via Docker CLI / socket
        proxy.
        """
        # TODO make verbose option
        print(f"[TERMINATOR] Killing container '{container_id}'. Reason: {reason}")

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "kill",
                container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()

            if proc.returncode == 0:
                # TODO make verbose, also do the same for below
                print(f"[TERMINATOR] Successfully killed {container_id}")
                return True
            else:
                print(
                    f"[TERMINATOR ERROR] Failed to kill {container_id}: "
                    f"{stderr.decode()}"
                )
                return False
        except Exception as e:
            print(f"[TERMINATOR EXCEPTION] Error killing container {container_id}: {e}")
            return False


async def _stream_container_logs_to_file(
    container_name: str, log_file_path: Path
) -> None:
    """Streams container stdout/stderr continuously to a log file on the host."""
    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "logs",
            "-f",
            container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        # Narrow the type for mypy (proc.stdout is guaranteed non-None when PIPE is
        # used)
        if proc.stdout is None:
            return

        with open(log_file_path, "a", encoding="utf-8") as f:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                f.write(line.decode("utf-8", errors="replace"))
                f.flush()
    except asyncio.CancelledError:
        if proc and proc.returncode is None:
            proc.terminate()
            await proc.wait()
    except Exception as e:
        print(f"[LOGGING ERROR] Streaming logs for {container_name} failed: {e}")


async def _run_async(
    *args: Any, check: bool = True, verbose: bool = False
) -> tuple[bytes, bytes]:
    """Utility to run shell commands without blocking the event loop."""
    if verbose:
        print(f"[CMD] {' '.join(args)}")

    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    out_str = stdout.decode(errors="replace").strip()
    err_str = stderr.decode(errors="replace").strip()

    if verbose:
        if out_str:
            print(f"[STDOUT] {out_str}")
        if err_str:
            print(f"[STDERR] {err_str}")

    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(args)}\nError: {err_str}")

    return stdout, stderr


def build_agent_environment(
    proxy_url: str, container_cert_path: str, sample_id: str, no_proxy_str: str
) -> dict[str, str | None]:
    """
    Constructs proxy, TLS certificate, and bypass environment variables for the sandbox
    container.
    """
    return {
        # Active L7 audit proxy for general web traffic
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        # Bypass list
        # TODO something about contradiction with --internal flag in network socket
        "NO_PROXY": no_proxy_str,
        "no_proxy": no_proxy_str,
        # CA Bundle for audited web traffic
        "REQUESTS_CA_BUNDLE": container_cert_path,
        "SSL_CERT_FILE": container_cert_path,
        "SAMPLE_ID": str(sample_id),
    }


async def _wait_for_proxy_health(
    proxy_name: str, proxy_port: int, timeout: int = 35, verbose: bool = False
) -> None:
    """Polls the proxy container until it accepts TCP connections."""
    if verbose:
        print("[Health Check] Waiting for proxy port to open...")

    start_time = time.time()

    while time.time() - start_time < timeout:
        # Simple socket ping to test if port 8080 is open
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "exec",
            proxy_name,
            "python3",
            "-c",
            f"import socket; s = socket.create_connection(('127.0.0.1', {proxy_port}), "
            f"timeout=1); s.close()",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

        # returncode == 0 means the TCP connection succeeded
        if proc.returncode == 0:
            if verbose:
                print(f"[Health Check] Proxy is up and listening on port {proxy_port}!")
            return

        await asyncio.sleep(1)

    # Timeout reached: clean up container and abort
    await _run_async("docker", "rm", "-f", proxy_name, check=False)
    raise RuntimeError(
        f"[Health Check] Proxy '{proxy_name}' failed to open port {proxy_port} within "
        f"{timeout}s."
    )


async def _extract_certs(proxy_name: str, certs_dir: Path) -> None:
    """Waits for mitmproxy to generate certs, then copies them to the host."""
    certs_dir.mkdir(parents=True, exist_ok=True)
    host_cert_path = certs_dir / "mitmproxy-ca-cert.pem"
    container_cert_path = "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"

    if host_cert_path.exists():
        return

    print("[Setup] Waiting for mitmproxy to generate CA certificates...")

    # Deterministic wait: poll until the file actually exists inside the container
    for _ in range(10):
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "exec",
            proxy_name,
            "ls",
            container_cert_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

        if proc.returncode == 0:
            await _run_async(
                "docker",
                "cp",
                f"{proxy_name}:{container_cert_path}",
                str(host_cert_path),
            )
            print("[Setup] CA certificates extracted successfully.")
            return

        await asyncio.sleep(1)

    raise RuntimeError("Timed out waiting for mitmproxy to generate certificates.")


class TelemetryData(TypedDict):
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    blocked_domains: list[str]
    domains_accessed: list[str]
    policy_violation: bool


def extract_sample_audit_telemetry(log_dir: Path, sample_id: str) -> TelemetryData:
    """Parse audit logs and extract network metrics/violations for a specific sample."""
    sample_audit_file = log_dir / f"sample_{sample_id}" / "audit_events.jsonl"

    telemetry: TelemetryData = {
        "total_requests": 0,
        "allowed_requests": 0,
        "blocked_requests": 0,
        "blocked_domains": [],
        "domains_accessed": [],
        "policy_violation": False,
    }

    if not sample_audit_file.exists():
        return telemetry

    with open(sample_audit_file, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)

            telemetry["total_requests"] += 1
            domain = event.get("host") or event.get("domain", "unknown")

            if event.get("action") == "BLOCK" or event.get("status_code") == 403:
                telemetry["blocked_requests"] += 1
                telemetry["policy_violation"] = True
                if domain not in telemetry["blocked_domains"]:
                    telemetry["blocked_domains"].append(domain)
            else:
                telemetry["allowed_requests"] += 1
                if domain not in telemetry["domains_accessed"]:
                    telemetry["domains_accessed"].append(domain)

    return telemetry


@sandboxenv(name="docker_audited")
class AuditedDockerSandboxEnvironment(DockerSandboxEnvironment):
    """Audited Sandbox inheriting natively from Inspect's Docker provider."""

    # environment variables to be defined when each sample is initialized
    resolved_id: str
    sample_id: str
    # TODO Check if we need all resolved_id, sample_id and container_id
    # TODO also check typing
    container_id: str
    container_ip: bytes
    auditor_config: AuditorConfig
    terminator: ContainerTerminator
    network_telemetry: TelemetryData

    # environmeent variables to be defined when task is initialized
    base_log_dir: Path

    _registry: dict = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._network_violation: str | None = None
        self._active_exec_tasks: set[asyncio.Task[Any]] = set()

    @classmethod
    async def _handle_proxy_socket_msg(
        cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Callback triggered whenever mitmproxy sends a request over the Unix socket.
        """
        data = await reader.read(4096)
        print("[HOST SOCKET RECV] Raw message received")
        if data:
            try:
                msg = json.loads(data.decode("utf-8"))
                # container_name = msg.get("container_id")
                reason = msg.get("reason")
                client_ip = msg.get("client_ip")

                # if action == "kill_container" and container_name:
                if cls.auditor_config.terminate_on_violation:
                    print(
                        f"[HOST AUDIT] Received kill request from proxy for container: "
                        f"{client_ip}"
                    )

                    await cls._registry[client_ip].terminate_for_policy(
                        reason, client_ip
                    )

            except ConnectionError:
                print("Connection Error ")
                pass

            except Exception as e:
                # TODO add to logging
                print(f"[HOST AUDIT] Error processing proxy socket message: {e}")

        writer.close()
        await writer.wait_closed()

    @property
    def network_violation(self) -> str | None:
        """Getter method for network violation."""
        return self._network_violation

    def mark_policy_violation(self, reason: str) -> None:
        """Terminal state mutation: once set, this sample remains policy-blocked."""
        if not self._network_violation:
            self._network_violation = reason

        for task in tuple(self._active_exec_tasks):
            if not task.done():
                task.cancel()

    def _raise_if_network_violation(
        self,
        cause: BaseException | None = None,
    ) -> None:
        if self._network_violation:
            raise AuditorPermissionError(
                f"Network access blocked by security policy: {self._network_violation}",
                violation_type="network",
            ) from cause

    async def terminate_for_policy(self, reason: str, container_id: str) -> None:
        """Marks terminal violation state and triggers container termination."""
        self.mark_policy_violation(reason)
        await self.terminator.terminate(
            container_id=self.container_id,
            reason=f"[POLICY VIOLATION] {reason}",
        )

        # TODO make verbose message
        print("terminate occured")

        for task in tuple(self._active_exec_tasks):
            if not task.done():
                # TODO is there a task name/description?
                print("[terminate] active task cancelled due to ")
                task.cancel()

    @classmethod
    async def task_init(  # type: ignore[override]
        cls,
        task_name: str,
        config: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        # Move
        cls.auditor_config = AuditorConfig.from_yaml(config)

        cls.base_log_dir = Path(cls.auditor_config.log_dir).resolve()

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if cls.auditor_config.setup_verbose:
            print(f"[Task init] Task Init started at time: {timestamp}")

        sub_folder_dir = cls.base_log_dir / str(timestamp)
        sub_folder_dir.mkdir(parents=True, exist_ok=True)
        cls.base_log_dir = sub_folder_dir

        # TODO This was supposed to make the inspect log files save in the same place as
        # the other logs but it doesnt work
        # os.environ["INSPECT_LOG_DIR"] = str(cls.base_log_dir)

        infra_log_dir = cls.base_log_dir / "infra_logs"
        infra_log_dir.mkdir(parents=True, exist_ok=True)

        # Prepare Socket Directory on Host
        # TODO In the future get this from config?
        socket_dir = Path("/tmp/inspect_audit")
        socket_dir.mkdir(parents=True, exist_ok=True)
        host_socket_path = socket_dir / "proxy.sock"
        container_config_path = "/etc/auditor/config.yaml"

        global _proxy_started, _socket_server

        async with _init_lock:
            if not _proxy_started:
                print(
                    f"[TASK INIT] Starting shared infrastructure "
                    f"('{cls.auditor_config.proxy_name}' and socket proxy)..."
                )

                # Start Unix Socket Server on Host
                if host_socket_path.exists():
                    host_socket_path.unlink()

                _socket_server = await asyncio.start_unix_server(
                    cls._handle_proxy_socket_msg, path=str(host_socket_path)
                )

                # Restrict socket access to owner only
                os.chmod(host_socket_path, 0o600)

                if cls.auditor_config.setup_verbose:
                    print(
                        f"[TASK INIT] Created UNIX socket server at: {host_socket_path}"
                    )

                # Create network & volume (non-blocking)
                await _run_async(
                    "docker",
                    "network",
                    "create",
                    cls.auditor_config.shared_network_name,
                    check=False,
                    verbose=cls.auditor_config.setup_verbose,
                )
                await _run_async(
                    "docker",
                    "volume",
                    "create",
                    "mitmproxy_certs",
                    check=False,
                    verbose=cls.auditor_config.setup_verbose,
                )

                # Boot Read-Only Docker Socket Proxy with Docker log rotation
                await _run_async(
                    "docker",
                    "rm",
                    "-f",
                    cls.auditor_config.socket_proxy_name,
                    check=False,
                    verbose=cls.auditor_config.setup_verbose,
                )

                socket_proxy_cmd = [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    cls.auditor_config.socket_proxy_name,
                    "--network",
                    cls.auditor_config.shared_network_name,
                    "--log-opt",
                    "max-size=10m",
                    "--log-opt",
                    "max-file=3",
                    "-v",
                    "/var/run/docker.sock:/var/run/docker.sock:ro",
                    "-e",
                    "CONTAINERS=1",
                    "-e",
                    "LOGS=1",
                    "-e",
                    "INFO=1",
                    "-e",
                    "EVENTS=1",
                    "-e",
                    "POST=0",
                    "-e",
                    "DELETE=0",
                    "-e",
                    "EXEC=0",
                    "tecnativa/docker-socket-proxy:latest",
                ]
                await _run_async(
                    *socket_proxy_cmd, verbose=cls.auditor_config.setup_verbose
                )

                # Stream Socket Proxy logs to infra_logs/socket_proxy.log
                socket_log_task = asyncio.create_task(
                    _stream_container_logs_to_file(
                        cls.auditor_config.socket_proxy_name,
                        infra_log_dir / "socket_proxy.log",
                    )
                )
                _infra_log_tasks.append(socket_log_task)

                # Build MITM Proxy Image (non-blocking)
                dockerfile_path = PACKAGE_DIR / "Dockerfile.proxy"
                build_context = PACKAGE_DIR.parent.parent
                await _run_async(
                    "docker",
                    "build",
                    "--network=host",
                    "-f",
                    str(dockerfile_path),
                    "-t",
                    "inspect-proxy:latest",
                    str(build_context),
                    verbose=cls.auditor_config.setup_verbose,
                )

                # Cleanup any existing containers from previous runs & Start MITM Proxy
                # with Socket Directory Mounted
                await _run_async(
                    "docker",
                    "rm",
                    "-f",
                    cls.auditor_config.proxy_name,
                    check=False,
                    verbose=cls.auditor_config.setup_verbose,
                )
                container_socket_path = f"/var/run/audit/{host_socket_path.name}"
                mitm_cmd = [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    cls.auditor_config.proxy_name,
                    "--network",
                    cls.auditor_config.shared_network_name,
                    "--log-opt",
                    "max-size=10m",
                    "--log-opt",
                    "max-file=3",
                    "-v",
                    f"{host_socket_path}:/var/run/proxy.sock",
                    "-v",
                    f"{str(CERTS_DIR.resolve())}:/home/mitmproxy/.mitmproxy",
                    "-v",
                    f"{PACKAGE_DIR / 'proxy_auditor.py'}:/scripts/proxy_auditor.py:ro",
                    "-v",
                    f"{cls.base_log_dir}:/logs",
                    # MOUNT SOCKET DIR INTO PROXY CONTAINER
                    "-v",
                    f"{socket_dir}:/var/run/audit",
                    "-v",
                    f"{config}:{container_config_path}:ro",
                    "-e",
                    f"CONFIG_PATH={container_config_path}",
                    "-e",
                    f"AUDIT_SOCKET_PATH={container_socket_path}",
                    "-e",
                    "PYTHONUNBUFFERED=1",
                    "inspect-proxy:latest",
                    "mitmdump",
                    "-s",
                    "/scripts/proxy_auditor.py",
                    "-w",
                    "/logs/shared_flows.mitm",
                    "--set",
                    "confdir=/home/mitmproxy/.mitmproxy",
                    "--set",
                    "block_global=false",
                    "--ignore-hosts",
                    cls.auditor_config.bypass_regex,
                ]
                if cls.auditor_config.setup_verbose:
                    mitm_cmd.extend(["--set", "term_log_verbosity=debug"])

                await _run_async(*mitm_cmd, verbose=cls.auditor_config.setup_verbose)

                # Stream MITM Proxy stdout/stderr to infra_logs/mitmproxy_container.log
                proxy_log_task = asyncio.create_task(
                    _stream_container_logs_to_file(
                        cls.auditor_config.proxy_name,
                        infra_log_dir / "mitmproxy_container.log",
                    )
                )

                _infra_log_tasks.append(proxy_log_task)

                # Wait for health and extract certs
                if cls.auditor_config.proxy_health_check:
                    try:
                        await _wait_for_proxy_health(
                            cls.auditor_config.proxy_name,
                            cls.auditor_config.proxy_port,
                            timeout=35,
                            verbose=cls.auditor_config.proxy_health_check_verbose,
                        )
                        await _extract_certs(cls.auditor_config.proxy_name, CERTS_DIR)
                    except Exception as exc:
                        # Capture stdout and stderr from the failing container
                        proc = await asyncio.create_subprocess_exec(
                            "docker",
                            "logs",
                            cls.auditor_config.proxy_name,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, stderr = await proc.communicate()

                        if cls.auditor_config.setup_verbose:
                            # TODO do we need this?
                            print(
                                "\n"
                                + "=" * 25
                                + f" {cls.auditor_config.proxy_name} LOGS "
                                + "=" * 25
                            )
                            print(stdout.decode("utf-8", errors="replace"))
                            print(stderr.decode("utf-8", errors="replace"))
                            print("=" * 60 + "\n")

                        raise RuntimeError(
                            f"Proxy container '{cls.auditor_config.proxy_name}' failed"
                            f"health check. See container logs above."
                        ) from exc

                _proxy_started = True

        await super().task_init(task_name, config=None)

    @classmethod
    async def sample_init(  # type: ignore[override]
        cls,
        task_name: str,
        config: None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, SandboxEnvironment]:
        metadata = metadata or {}

        # Resolve Sample ID safely with proper fallbacks
        field_key = cls.auditor_config.sample_id_field or "id"
        raw_id = metadata.get(field_key) or metadata.get("id")
        resolved_id = (
            str(raw_id).strip()
            if raw_id and str(raw_id).strip()
            else f"sample_{uuid.uuid4().hex[:8]}"
        )

        if cls.auditor_config.setup_verbose:
            print(f"[SAMPLE INIT] Sample ID: {resolved_id}")

        # Construct the unique network name for this sample
        internal_net_name = f"agent_net_{resolved_id}"

        # 3. Dynamically create the isolated network
        await _run_async(
            "docker", "network", "create", internal_net_name, "--internal", check=False
        )

        # 4. Attach the proxy singleton to this sample's network
        await _run_async(
            "docker",
            "network",
            "connect",
            internal_net_name,
            cls.auditor_config.proxy_name,
            check=False,
        )

        # 5. Create ComposeConfig for the agent on this internal network
        # proxy_url = f"http://{cls.auditor_config.proxy_name}:{cls.auditor_config.proxy_port}"
        proxy_url = f"http://{resolved_id}@{cls.auditor_config.proxy_name}:{cls.auditor_config.proxy_port}"

        host_cert_file = (CERTS_DIR / "mitmproxy-ca-cert.pem").resolve()

        # Volume mount string: Host_Path:Container_Path:Mode
        agent_volumes = [f"{str(host_cert_file)}:{CONTAINER_CERT_PATH}:ro"]

        agent_env = build_agent_environment(
            proxy_url=proxy_url,
            container_cert_path=CONTAINER_CERT_PATH,
            sample_id=resolved_id,
            no_proxy_str=cls.auditor_config.no_proxy_str,
        )

        compose_config = ComposeConfig(
            services={
                "default": ComposeService(
                    build=ComposeBuild(
                        context=str(PACKAGE_DIR), dockerfile="Dockerfile.agent"
                    ),
                    environment=agent_env,
                    volumes=agent_volumes,
                    networks=[internal_net_name],
                    command=["tail", "-f", "/dev/null"],
                )
            },
            networks={
                internal_net_name: {"external": True}  # Pre-created via _run_async
            },
        )

        environments = await super().sample_init(
            task_name=task_name,
            config=compose_config,
            metadata=metadata,
        )

        # Attach instance attributes to every created SandboxEnvironment instance
        for env in environments.values():
            env.__class__ = cls

            audited_env = cast(AuditedDockerSandboxEnvironment, env)

            audited_env.resolved_id = resolved_id
            audited_env.sample_id = resolved_id
            audited_env.auditor_config = cls.auditor_config
            audited_env.terminator = ContainerTerminator()
            audited_env._network_violation = ""
            audited_env._active_exec_tasks = set()

        for service_name, sample_env in environments.items():
            if service_name == "default":
                # cls._registry[resolved_id] = sample_env
                # Get short container ID
                host_res = await env.exec(["hostname"])
                # TODO delete
                # container_id = host_res.stdout.strip()
                raw_stdout = host_res.stdout
                stdout_str = (
                    raw_stdout.decode("utf-8")
                    if isinstance(raw_stdout, bytes)
                    else raw_stdout
                )
                container_id = stdout_str.strip()
                audited_env.container_id = container_id
                # env.container_id = container_id

                # TODO error handle
                # 1. Fetch IP assigned on the internal network
                try:
                    inspect_res, stderr = await _run_async(
                        "docker",
                        "inspect",
                        "-f",
                        f"{{{{.NetworkSettings.Networks.{internal_net_name}.IPAddress}}}}",
                        container_id,
                    )
                    container_ip = inspect_res.strip()
                    audited_env.container_ip = container_ip
                except Exception:
                    stderr_str = (
                        stderr.decode("utf-8") if isinstance(stderr, bytes) else stderr
                    )
                    print(
                        f"Container {container_id} is not connected to network "
                        f"{internal_net_name}: {stderr_str.strip()}"
                    )

                cls._registry[container_ip.decode("utf-8")] = sample_env

        return environments

    @classmethod
    async def _collect_container_telemetry(
        cls,
        service_name: str,
        sample_env: SandboxEnvironment,
        sample_id: str,
        sample_dir: Path,
    ) -> dict[str, Any]:
        """
        Asynchronously collects logs, command history, and metadata for a single
        container service.
        """
        container_info: dict[str, Any] = {
            "service_name": service_name,
            "container_id": None,
            "status": "unknown",
            "bash_history_saved": False,
            "docker_logs_saved": False,
            "errors": [],
        }

        try:
            # Resolve Container ID/Name safely (Attribute check first -> exec fallback)
            container_id = getattr(sample_env, "container_id", None) or getattr(
                sample_env, "name", None
            )

            if not container_id:
                try:
                    res = await sample_env.exec(["hostname"])
                    if res.returncode == 0 and res.stdout.strip():
                        container_id = res.stdout.strip()
                except Exception as exec_err:
                    # TODO delete
                    # container_info["errors"].append(f"Hostname exec failed:
                    # {exec_err}") # supposed to be part of above
                    if isinstance(container_info.get("errors"), list):
                        container_info["errors"].append(
                            f"Hostname exec failed: {exec_err}"
                        )
            target_name = container_id or f"{sample_id}_{service_name}"
            container_info["container_id"] = target_name

            # 2. Save standard Docker Logs (PID 1 / background daemons / sidecar logs)
            if cls.auditor_config.save_docker_logs:
                try:
                    log_file = sample_dir / f"{service_name}_docker.log"
                    # Call stdout/stderr docker logs asynchronously
                    proc = await asyncio.create_subprocess_exec(
                        "docker",
                        "logs",
                        "--timestamps",
                        target_name,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()
                    log_content = stdout.decode(
                        "utf-8", errors="replace"
                    ) + stderr.decode("utf-8", errors="replace")

                    log_file.write_text(log_content, encoding="utf-8")
                    container_info["docker_logs_saved"] = True
                    container_info["status"] = "logs_extracted"
                except Exception as log_err:
                    container_info["errors"].append(
                        f"Failed to fetch docker logs: {log_err}"
                    )

            # 3. Extract Bash History (Specifically for the main agent container)
            if service_name == "default":
                try:
                    hist_res = await sample_env.exec(["cat", "/root/.bash_history"])
                    if hist_res.returncode == 0 and hist_res.stdout.strip():
                        hist_path = sample_dir / "agent_bash_history.log"
                        hist_path.write_text(hist_res.stdout, encoding="utf-8")
                        container_info["bash_history_saved"] = True
                except Exception as hist_err:
                    container_info["errors"].append(
                        f"Failed to fetch bash history: {hist_err}"
                    )

        except Exception as e:
            container_info["errors"].append(f"Uncaught collection error: {e}")

        return container_info

    @classmethod
    async def sample_cleanup(
        cls,
        task_name: str,
        config: Any,
        environments: dict[str, SandboxEnvironment],
        interrupted: bool,
    ) -> None:
        """
        Save container logs and collect L7 telemetry before sandbox teardown, then clean
        up internal networks.
        """

        # 0. Retrieve primary environment and sample metadata
        env = next(iter(environments.values()), None)
        sample_id = (
            getattr(env, "resolved_id", None)
            or getattr(env, "sample_id", None)
            or getattr(env, "project_name", None)
            or "unknown_sample"
        )

        # Prepare isolated per-sample log directory
        sample_dir = cls.base_log_dir / f"sample_{sample_id}"
        sample_dir.mkdir(parents=True, exist_ok=True)

        print(
            f"[CLEANUP] Starting cleanup for sample '{sample_id}'"
            f"(interrupted={interrupted})"
        )

        # Wrap telemetry & log gathering in try-finally so system resources are ALWAYS
        # freed
        try:
            # 1. Parallel collection of container logs & shell history
            container_reports = []
            if cls.auditor_config.save_docker_logs:
                tasks = [
                    cls._collect_container_telemetry(
                        service_name, sample_env, sample_id, sample_dir
                    )
                    for service_name, sample_env in environments.items()
                ]
                # Gather all container logs concurrently
                container_reports = await asyncio.gather(*tasks, return_exceptions=True)

            # 2. Extract & Inject L7 Network Audit Telemetry
            network_telemetry: TelemetryData
            try:
                network_telemetry = extract_sample_audit_telemetry(
                    cls.base_log_dir, sample_id
                )
                if env:
                    # Attach telemetry directly onto environment instance for Inspect AI
                    # serialization
                    audited_env = cast(AuditedDockerSandboxEnvironment, env)
                    audited_env.network_telemetry = network_telemetry
                    print(
                        f"[CLEANUP] Telemetry attached for '{sample_id}': "
                        f"Requests={network_telemetry.get('total_requests', 0)}, "
                        f"Blocked={network_telemetry.get('blocked_requests', 0)}, "
                        f"Violation={network_telemetry.get('policy_violation', False)}"
                    )
            except Exception as e:
                print(
                    f"[CLEANUP WARNING] Failed to parse network audit telemetry for "
                    f"'{sample_id}': {e}"
                )

            # 3. Dump master audit manifest (structured JSON aggregation)
            manifest_path = sample_dir / "audit_manifest.json"
            manifest_data = {
                "sample_id": sample_id,
                "task_name": task_name,
                "interrupted": interrupted,
                "network_telemetry": network_telemetry,
                "container_telemetry": [
                    rep if isinstance(rep, dict) else {"error": str(rep)}
                    for rep in container_reports
                ],
                "exec_buffer": getattr(
                    env, "exec_buffer", []
                ),  # Optional: runtime command buffer if stored
            }
            manifest_path.write_text(
                json.dumps(manifest_data, indent=2), encoding="utf-8"
            )

        except Exception as general_err:
            print(
                f"[CLEANUP ERROR] Unexpected error during log collection stage: "
                f"{general_err}"
            )

        finally:
            # 4. Destroy agent containers via parent sample_cleanup
            try:
                print(
                    "[CLEANUP] Invoking super().sample_cleanup for sample "
                    f"'{sample_id}'..."
                )
                await super().sample_cleanup(
                    task_name,
                    config,
                    environments,
                    interrupted,
                )
            except Exception as super_err:
                print(f"[CLEANUP ERROR] Parent sample_cleanup failed: {super_err}")

            # Clean up dynamic internal network (AFTER agent containers are destroyed)
            if sample_id and sample_id != "unknown_sample":
                internal_net_name = f"agent_net_{sample_id}"
                print(
                    f"[CLEANUP] Tearing down internal network '{internal_net_name}'..."
                )

                try:
                    # Step A: Force-disconnect shared proxy
                    await _run_async(
                        "docker",
                        "network",
                        "disconnect",
                        "-f",
                        internal_net_name,
                        cls.auditor_config.proxy_name,
                        check=False,
                    )

                    # Step B: Remove isolated network
                    await _run_async(
                        "docker", "network", "rm", internal_net_name, check=False
                    )
                    print(
                        f"[CLEANUP] Successfully removed network '{internal_net_name}'"
                    )

                except Exception as net_err:
                    print(
                        f"[CLEANUP ERROR] Failed to remove internal network "
                        f"'{internal_net_name}': {net_err}"
                    )

    @classmethod
    async def task_cleanup(  # type: ignore[override]
        cls, task_name: str, config: str | None = None, cleanup: bool = True
    ) -> None:
        """Runs ONCE at the end. Tears down the shared proxy and network."""
        print(f"[Task Cleanup] Tearing down {cls.auditor_config.proxy_name}...")

        global _proxy_started, _socket_server

        if "_socket_server" in globals() and _socket_server:
            _socket_server.close()
            await _socket_server.wait_closed()
            _socket_server = None

        host_socket_path = Path("/tmp/inspect_audit/proxy.sock")
        if host_socket_path.exists():
            try:
                host_socket_path.unlink()
            except Exception:
                pass

        if cls.base_log_dir:
            try:
                # Cancel background log tailing tasks
                for task in _infra_log_tasks:
                    task.cancel()
                await asyncio.gather(*_infra_log_tasks, return_exceptions=True)
                _infra_log_tasks.clear()

            except Exception as e:
                print(f"[Task Cleanup] Failed to save proxy stdout: {e}")

        try:
            # Remove Socket Proxy container
            await _run_async(
                "docker", "rm", "-f", cls.auditor_config.socket_proxy_name, check=False
            )

            # Remove MITM Proxy container
            await _run_async(
                "docker", "rm", "-f", cls.auditor_config.proxy_name, check=False
            )

            # Remove shared bridge network
            await _run_async(
                "docker",
                "network",
                "rm",
                cls.auditor_config.shared_network_name,
                check=False,
            )

        except Exception as e:
            print(f"[TASK CLEANUP] Error during teardown: {e}")
        finally:
            _proxy_started = False

        await super().task_cleanup(task_name=task_name, config=config, cleanup=cleanup)

    # @classmethod
    # def config_serialize(cls, config: Any) -> Any:
    #     return super().config_serialize(config)

    @classmethod
    def config_serialize(self) -> dict[str, Any] | str:
        """Serialize the sandbox environment configuration."""
        # Return your custom config directly (e.g., Pydantic model dump or dict)
        if hasattr(self, "auditor_config") and self.auditor_config:
            return self.auditor_config.model_dump()

        return {}

    @classmethod
    def config_deserialize(  # type: ignore[override]
        cls, config: Any = None, **kwargs: Any
    ) -> "AuditedDockerSandboxEnvironment":
        # 1. Existing instance pass-through
        if isinstance(config, AuditedDockerSandboxEnvironment):
            return config

        # 2. Dict input unpacking (e.g. {"service": "default", "working_dir": "/app"})
        if isinstance(config, dict):
            return cls(**config, **kwargs)

        # 3. String, None, or kwargs (e.g. "config.yaml", or service="default")
        return cls(config=config, **kwargs)

    async def exec(
        self,
        cmd: list[str],
        input: str | bytes | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str | None = None,
        timeout: int | None = None,
        timeout_retry: bool = True,
        concurrency: bool = True,
    ) -> ExecResult[str]:

        # Guard 1
        self._raise_if_network_violation()

        # Command policy
        cmd_str = " ".join(cmd)

        for rule in self.auditor_config.command_rules:
            if re.search(rule.pattern, cmd_str, flags=re.DOTALL):
                violation_msg = f"Command rule violation [{rule.name}]: {rule.message}"
                # TODO Add to verbose
                print(f"[COMMAND VIOLATION] {violation_msg}")

                if self.auditor_config.terminate_on_violation:
                    # TODO is this supposed to be resolved_id?
                    await self.terminate_for_policy(violation_msg, self.resolved_id)
                else:
                    self.mark_policy_violation(violation_msg)

                raise AuditorPermissionError(
                    f"Command blocked by policy [{rule.name}]: {rule.message}"
                )

        task = asyncio.current_task()
        assert task is not None
        self._active_exec_tasks.add(task)

        try:
            result = await super().exec(
                cmd=cmd,
                input=input,
                cwd=cwd,
                env=env,
                user=user,
                timeout=timeout,
                timeout_retry=timeout_retry,
                concurrency=concurrency,
            )

        except asyncio.CancelledError as exc:
            # Guard 2
            self._raise_if_network_violation(exc)
            raise

        finally:
            self._active_exec_tasks.discard(task)

        # Guard 3
        self._raise_if_network_violation()

        return result
