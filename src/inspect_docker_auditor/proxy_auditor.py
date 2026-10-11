import ipaddress
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from mitmproxy import ctx, http

from inspect_docker_auditor.config import AuditorConfig, NetworkRuleConfig

sys.path.insert(0, "/app/src")

# set socket_path global variable
SOCKET_PATH = "/var/run/audit/proxy.sock"


class ProxyAuditor:
    def __init__(self) -> None:
        # Determine path from env var or default container path
        config_path = os.getenv("CONFIG_PATH")

        # Clean single-line instantiation
        self.config = AuditorConfig.from_yaml(config_path)
        print("config in proxy: ", self.config)

        # get network rules from config
        raw_rules = self.config.network_rules
        validated_rules = []
        for raw_rule in raw_rules:
            try:
                validated_rules.append(NetworkRuleConfig.model_validate(raw_rule))

            except Exception as err:
                rule_name = (
                    raw_rule.get("name", "unnamed")
                    if isinstance(raw_rule, dict)
                    else "unnamed"
                )
                print(
                    f"[mitmproxy] ERROR: Invalid rule schema for '{rule_name}': {err}"
                )
        self.rules = validated_rules

        # Instance configuration
        self.docker_socket_proxy_url = (
            f"http://{self.config.socket_proxy_name}:{self.config.socket_proxy_port}"
        )
        self.cache_ttl_seconds = self.config.cache_ttl

        # Instance state cache: { ip_address: (container_name, expiration_timestamp) }
        self._ip_container_cache: dict[str, tuple[str, float]] = {}

        self._cache_lock = threading.Lock()

    def _is_internal_host(self, host: str) -> tuple[bool, str]:
        """
        Resolves hostname and checks if target is an internal, private, or reserved IP.
        Returns tuple: (is_internal: bool, resolved_ip_or_details: str)
        """
        # 1. Direct host match
        if host.lower() in ("localhost", "localhost.localdomain"):
            return True, "127.0.0.1"

        try:
            # 2. Resolve DNS to catch DNS-rebinding (e.g. evil.com -> 127.0.0.1)
            ip_str = socket.gethostbyname(host)
            ip = ipaddress.ip_address(ip_str)

            is_internal = (
                ip.is_private  # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                or ip.is_loopback  # 127.0.0.0/8
                or ip.is_link_local  # 169.254.0.0/16 (AWS/GCP Metadata 169.254.169.254)
                or ip.is_reserved  # IETF reserved
            )
            return is_internal, str(ip)

        except Exception:
            # If DNS resolution fails inside proxy, treat as unknown/unreachable
            return False, "unresolved"

    def _check_egress_violation(self, flow: http.HTTPFlow) -> dict | None:
        """
        Checks whether an HTTP flow targets an internal network resource and returns
        violation details if egress is prohibited.
        """
        host = flow.request.pretty_host
        is_internal, resolved_ip = self._is_internal_host(host)

        if is_internal:
            return {
                "rule_name": "System_Internal_Egress_Block",
                "status_code": 403,
                "message": (
                    "Access to internal network resource"
                    f"({host} -> {resolved_ip}) is prohibited.",
                ),
            }
        return None

    def log_to_file(self, message: str | dict, sample_id: str | None = None) -> None:
        """
        Write audit events safely across concurrent workers using atomic POSIX appends.
        """
        # TODO get rid of getattr (i.e. find out where it actually is)
        # Dynamically resolve per-sample or base log directory
        base_dir = getattr(self, "sample_log_dir", None) or getattr(
            self, "base_log_dir", Path("/logs")
        )

        if base_dir is None:
            base_dir = "/logs"

        target_dir = Path(base_dir)

        if sample_id:
            target_dir = target_dir / "samples" / sample_id
        else:
            target_dir = target_dir

        target_dir.mkdir(parents=True, exist_ok=True)
        log_path = target_dir / "audit_events.jsonl"

        # Standardize input into a dictionary with timestamps
        if isinstance(message, dict):
            log_dict = dict(message)
            if "timestamp" not in log_dict:
                log_dict["timestamp"] = datetime.now().isoformat()
        else:
            log_dict = {
                "message": str(message),
                "timestamp": datetime.now().isoformat(),
            }

        # Safe Field Truncation: Truncate large string values BEFORE json.dumps
        for key, value in list(log_dict.items()):
            if isinstance(value, str) and len(value) > 1500:
                log_dict[key] = value[:1500] + "... [TRUNCATED]"

        # Serialize to JSON
        json_str = json.dumps(log_dict)
        encoded_message = f"{json_str}\n".encode()

        # POSIX Buffer Guard: If line still exceeds 4KB atomic threshold, drop payload
        # safely
        if len(encoded_message) > 4000:
            fallback_dict = {
                "event": log_dict.get("event", "LOG_TRUNCATED"),
                "reason": "Log entry exceeded 4KB POSIX atomic buffer limit",
                "timestamp": log_dict.get("timestamp"),
                "summary": str(log_dict)[:300] + "... [TRUNCATED]",
            }
            encoded_message = f"{json.dumps(fallback_dict)}\n".encode()

        # Low-level POSIX atomic append
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o666)
        try:
            os.write(fd, encoded_message)
        finally:
            os.close(fd)

    def evaluate_rule(self, rule: NetworkRuleConfig, flow: http.HTTPFlow) -> bool:
        host = flow.request.pretty_host
        path = flow.request.path
        method = flow.request.method

        # TODO make a cleaner rule checking method
        # Match domain if no domains listed OR host matches one of the specified domains
        domain_match = not rule.domains or any(
            host == d or host.endswith(f".{d}") for d in rule.domains
        )

        # Match path if no paths listed OR path starts with one of the specified paths
        path_match = not rule.paths or any(path.startswith(p) for p in rule.paths)

        # Match method if no methods listed OR method is in the list
        method_match = not rule.methods or method in rule.methods

        return domain_match and path_match and method_match

    def send_socket_signal(self, client_ip: str, reason: str) -> None:
        """
        Sends a non-blocking notification to the host Python process via Unix domain
        socket.
        """

        # Read from environment variable injected via Docker -e AUDIT_SOCKET_PATH
        socket_path = os.getenv("AUDIT_SOCKET_PATH", "/var/run/audit/proxy.sock")

        payload = json.dumps({"reason": reason, "client_ip": client_ip}).encode("utf-8")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(socket_path)
            client.sendall(payload)

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercept, evaluate, and audit HTTP requests with dynamic container killing.
        """
        target_url = flow.request.pretty_url
        method = flow.request.method
        print("[MITMPROXY] client ip: ", flow.client_conn.peername[0])

        log_mitmproxy = self.config.save_mitmproxy_logs

        # Client Identification & Telemetry Setup
        client_ip = flow.client_conn.peername[0]

        print(f"[mitmproxy] Intercepted [{client_ip}]: {method} {target_url}")

        audit_entry = {
            "timestamp": time.time(),
            "client_ip": client_ip,
            # "container_name": container_name,
            # "sample_id": sample_id,
            "method": method,
            "url": target_url,
            "action": "ALLOW",
            "matched_rule": None,
        }

        # System Guardrail: Internal Egress Check
        egress_violation = self._check_egress_violation(flow)
        if egress_violation:
            self._handle_block(
                flow=flow,
                audit_entry=audit_entry,
                rule_name=egress_violation["rule_name"],
                status_code=egress_violation["status_code"],
                message=egress_violation["message"],
                # container_name=container_name,
                log_mitmproxy=log_mitmproxy,
                is_system_rule=True,
            )
            return

        # rule check
        for rule in self.rules:
            if not self.evaluate_rule(rule, flow):
                continue

            # Convert Pydantic NetworkRuleConfig to dict if necessary
            # rule_dict = (
            #     rule.model_dump(mode="json") if hasattr(rule, "model_dump") else rule
            # )
            rule_dict = rule if isinstance(rule, dict) else rule.model_dump(mode="json")

            rule_name = rule_dict.get("name", "Unnamed Rule")
            raw_action = rule_dict.get("action", "BLOCK")
            action_type = str(raw_action).upper()
            status_code = rule_dict.get("status_code", 403)
            message = rule_dict.get("message", "Blocked by Policy Rule")

            print(
                f"[mitmproxy] Rule matched for '{client_ip}': {rule_name}"
                f"(Action: {action_type})"
            )

            if action_type == "BLOCK":
                self._handle_block(
                    flow=flow,
                    audit_entry=audit_entry,
                    rule_name=rule_name,
                    status_code=status_code,
                    message=message,
                    log_mitmproxy=log_mitmproxy,
                    is_system_rule=False,
                )
                return

        # if everything passes
        if log_mitmproxy:
            self.log_to_file(audit_entry)

    def _handle_block(
        self,
        flow: http.HTTPFlow,
        audit_entry: dict,
        rule_name: str,
        status_code: int,
        message: str,
        log_mitmproxy: bool,
        is_system_rule: bool = False,
    ) -> None:
        """
        Helper to write block audit entries, issue 403 response, and trigger container
        kill switch.
        """
        timestamp = datetime.now().isoformat()

        client_ip = flow.client_conn.peername[0]

        # Update audit entry with standardized schema for extract_sample_audit_telemetry
        audit_entry.update(
            {
                "event": "NETWORK_VIOLATION",
                "action": "BLOCK",
                "blocked": True,
                "matched_rule": rule_name,
                "reason": message,
                "timestamp": timestamp,
            }
        )

        if log_mitmproxy:
            self.log_to_file(audit_entry)

        tag = "SYSTEM " if is_system_rule else ""
        ctx.log.warn(
            f"[AUDIT PROXY] BLOCKED {tag}({rule_name}) from {client_ip}: "
            f"{flow.request.pretty_url}"
        )

        # Return 403 Forbidden response to client
        flow.response = http.Response.make(
            status_code,
            f"Policy Violation [{rule_name}]: {message}".encode(),
            {
                "Content-Type": "text/plain",
                "Audit-Blocked": "true",
            },
        )

        # Notify the host socket server of the violation
        if self.config.terminate_on_violation:
            try:
                self.send_socket_signal(
                    client_ip=flow.client_conn.peername[0],
                    reason=f"Blocked request to {flow.request.pretty_host}",
                )
                ctx.log.error(
                    f"[AUDIT PROXY] Termination signal sent over socket for {client_ip}"
                )
            except Exception as err:
                ctx.log.error(
                    "[AUDIT PROXY] Failed to send termination signal over socket for "
                    f"{client_ip}: {err}"
                )


addons = [ProxyAuditor()]
