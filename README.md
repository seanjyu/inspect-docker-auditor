# inspect-docker-auditor

An audited Docker sandbox environment for Inspect AI that uses a mitmproxy to log and enforces security policies on network traffic and shell command execution inside inspect AI evaluation containers.

## Key Features:
- Granular L7 Network Control: Enforce strict egress policies by filtering target domains, URL path prefixes, and high-risk HTTP methods (e.g., permitting GET requests for reading while blocking POST or PUT calls to prevent exfiltration).

- L7 Interception & TLS Handling: Intercepts HTTP/HTTPS traffic using `mitmproxy` with automatic CA certificate generation, host extraction, and container injection (`REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`), streaming atomic JSONL logs of all request metadata.

- Shell Command Interception: Intercept Inspect AI's exec() method to evaluate shell commands against regex-based rules prior to execution, blocking unauthorized system operations.

- Flexible Policy Enforcement: Toggle between soft-blocking (returning 403 HTTP errors or execution permission errors) and hard termination (immediately killing the container via Docker) upon rule violations. 

- Atomic Telemetry & Logging: POSIX atomic JSONL event logging, container stdout/stderr log streaming, bash shell history collection, and structured master audit manifests

-  To prevent the agent from issuing further commands during this teardown window, `inspect-docker-auditor` immediately cancels active Inspect AI `exec()` tasks at the framework level the moment a violation is flagged.

- Agent containers sit on an internal-only network such that the sole route out is the proxy sidecar. If an agent happens to unnset the CA env vars it will yield no network and not an unaudited network.

- The proxy sidecar has no direct Docker daemon access; instead, violation signals are dispatched over a restricted host-mounted Unix domain socket to the Inspect AI host runner, which safely handles container termination.


## Threat Model and Limitations
This system is designed for observability and policy enforcement on evaluation agents rather than functioning as a hardened security boundary. Before using inspect-docker-auditor, please note the following weaknesses/threat vectors:
- Shell regex filter is a coarse heuristic (ba""sh, base64 evade it)
- The "Kill on violation" command will only occur after the violation is triggered meaning that there is a small window between when a violation command is sent from the MITM proxy and the actual docker shutdown is activated.
- This framework does not track Non-HTTP traffic, specifically:
    - Raw TCP/UDP packets and non-HTTP protocols are hard-dropped at the kernel layer by network isolation rather than forwarded to the proxy. Consequently, unauthorized non-HTTP egress is blocked safely but leaves no application-level audit trail in the logs.
    - Because Docker's embedded DNS resolver operates independently of the proxy, agents can still resolve external domain names to IP addresses locally. While connection attempts to those IPs are subsequently dropped, the DNS lookups themselves represent an unmonitored telemetry gap.
    - Because the agent container and the `mitmdump` sidecar share the same isolated internal subnet, the agent container can theoretically reach the proxy's listening port directly via container IP. While the sidecar runs headless with no management UI or administrative control plane, this shares a local network surface area rather than a strictly unidirectional data path.

## System Requirements
- Python 3.12 or higher
- Docker Engine/Docker Desktop
## Install
1. Clone this repo 
``` bash
git clone https://github.com/seanjyu/inspect-docker-auditor
```
OPTIONAL - Create and activate python virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```
2. Install the package and dependencies
```bash
pip install .
```
Alternatively use developer mode (if you want to modify the code).
```bash
pip install -e ".[dev]"
```

## Quickstart
The following example is a quick example of how to use the docker auditor. A more in depth example can be found here
1. Setup a config.yaml file with specific rules (note, most of the config variables have default values, a full example can be found [here]())
```yaml
network_rules:
  - name: "block_example_domain"
    domains: ["example.com"]
    action: "BLOCK"
    status_code: 403

terminate_on_violation: false
```

2. Import inspect_docker_auditor at the top of your evaluation file to register the "docker_audited" provider. Then, pass your config.yaml path inside the task's sandbox tuple: sandbox=("docker_audited", config_path)
```python
from pathlib import Path
from inspect_ai import Task, task, eval as inspect_eval
from inspect_ai.scorer import includes
import inspect_docker_auditor  # Registers 'docker_audited' sandbox provider


# Define config as an input
@task
def your_inspect_AI_task(config_path: str | Path = "config.yaml") -> Task:
    return Task(
        dataset=your_dataset,
        plan=your_plan,
        sandbox=(
            "docker_audited",
            str(config_path),
        ),  # define the sandbox to be "docker_audited" and supply the config_path
        scorer=includes(),
    )


if __name__ == "__main__":
    inspect_eval(audited_eval_task())
```
3. Open docker desktop, then execute the script
```python
python your_task.py
```

4. Inspect logs, HTTP traffic captures, and command execution traces will be written to the output directory specified in your config.yaml (defaults to ./auditor_logs/).

<!-- ## Documentation and Testing
- Further details regarding the architecture can be found [here](docs/architecture.md)
- Testing for this framework was done through pytest, more details can be found [here](tests/testing.md)
- A roadmap of future features and considerations can be found [here](docs/roadmap.md) -->
