# Config

The main configuration object accepts the following fields:

- `sample_id_field`: `str | None` — Identifier field name (Default: `None`).

- `shared_network_name`: `str` — Docker shared network name (Default: `""`).

- `proxy_name`: `str` — Name of the proxy container (Default: `""`).

- `proxy_port`: `int` — Port for the proxy service (Default: `8080`).

- `socket_proxy_name`: `str` — Name of the socket proxy (default: `""`).

- `socket_proxy_port`: `int` — Port for the socket proxy (Default: `2375`).

- `setup_verbose`: `bool` — Enable verbose setup output (Default: `True`).

- `proxy_health_check`: `bool` — Enable proxy health checks (Default: `True`).

- `proxy_health_check_verbose`: `bool` — Enable verbose health checks (Default: `True`).

- `log_dir`: `str` — Directory path for logs (Default: `"logs"`).

- `save_docker_logs`: `bool` — Flag to save Docker logs (Default: `True`).

- `terminate_on_violation`: `bool` — Terminate execution on security violation (Default: `False`).

- `cache_ttl`: `int` — Cache time-to-live in seconds (Default: `30`).

- `save_mitmproxy_logs`: `bool` — Flag to save mitmproxy logs (Default: `True`).

- `network_rules`: `list[NetworkRuleConfig]` — List of network security rules (Default: `[]`).

- `bypass`: `list[str]` — List of hosts/IPs to bypass/ignore (Default: `[]`).

- `command_rules`: `list[CommandRuleConfig]` — List of command execution rules (Default: `[]`).

## Command Execution Rules (`CommandRuleConfig`)

### Accepted Variables

- `name`: `str` — Unique name/identifier for the rule.
- `pattern`: `str` — Regular expression pattern matched against bash commands (compiled and validated at load time).
- `action`: `Literal["BLOCK", "ALLOW", "WARN"]` — Action to take upon match (Default: `"BLOCK"`).
- `message`: `str` — Custom notification or error message (Default: `"Command execution prohibited by policy"`).

### Minimal Example

```yaml
command_rules:
  - name: block-rm-rf
    pattern: "rm\\s+-[rf]+"
    action: BLOCK
    message: "Recursive file deletion is not allowed."

```

## Network Rules (`NetworkRuleConfig`)

### Accepted Variables

- `name`: `str` — Unique name/identifier for the rule.
- `enabled`: `bool` — Whether the rule is active (Default: `True`).
- `domains`: `list[str]` — List of target domains to match (Default: `[]`).
- `paths`: `list[str]` — List of URL paths to match (Default: `[]`).
- `methods`: `list[str]` — List of HTTP methods to match, e.g., `GET`, `POST` (Default: `[]`).
- `action`: `Literal["BLOCK", "ALLOW", "WARN"]` — Action to take upon match (Default: `"BLOCK"`).
- `status_code`: `int` — HTTP status code returned on block (Default: `403`).
- `message`: `str` — Response or log message (Default: `"Request blocked by security policy"`).

### Minimal Example

```yaml
network_rules:
  - name: block-admin-access
    enabled: true
    domains:
      - "api.example.com"
    paths:
      - "/admin/*"
    methods:
      - "POST"
      - "PUT"
    action: BLOCK
    status_code: 403
    message: "Administrative endpoints are restricted."

```
