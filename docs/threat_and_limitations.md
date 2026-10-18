# Trust Boundaries/Threat model
The intended adversary for this framework is an untrusted, autonomous LLM agent. It must be strictly blocked from reaching the host Docker daemon, private internal subnets, cloud metadata endpoints (169.254.169.254), and unapproved public egress. The L7 audit and regex filters are defence-in-depth, not a security boundary. The hard boundary is Docker --internal network isolation plus the host-only daemon access.

## Trust Hierarchy

- Agent container: Untrusted; network access routed exclusively via the proxy sidecar; zero Docker daemon or socket access.

- mitmdump sidecar: Semi-trusted; enforces L7 policy; possesses read-only, filtered Docker API access via a socket proxy (restricted strictly to container inspection, with DELETE=0 and EXEC=0); signals violations out-of-band.

- Host runner: Trusted; sole daemon-write authority; executes container termination (docker kill).

# Limitations
This system is designed for deep audit telemetry and policy enforcement on evaluation agents rather than functioning as an absolute kernel-level security barrier. The hard security boundary is enforced at the infrastructure layer via Docker --internal network isolation and host-only daemon access; L7 proxy inspection and regex filters serve as defence-in-depth layers.

Before using inspect-docker-auditor, note the following known limitations and threat vectors:

Non-HTTP Egress & Subnet Reachability Gaps
- External Egress
    - Packets destined for external public IP addresses are hard-dropped at the kernel layer by Docker's --internal network isolation.

- Subnet Reachability
    - Because the proxy container shares the sample's internal network (agent_net_<id>), the agent can theoretically send raw TCP packets to the proxy container's IP address. However, because mitmdump only listens on the configured proxy port (default: 8080) and exposes no other services, any raw TCP or non-HTTP traffic sent to other ports results in a TCP Connection Refused.

- DNS Resolution Side-Channel
    - Because Docker's embedded DNS resolver (127.0.0.11) operates independently of the proxy, agents can still resolve external domain names to IP addresses locally. While connection attempts to those IPs are subsequently dropped, the DNS lookups represent an unmonitored telemetry gap.

- Logging Gap
    - In all cases, non-HTTP and raw protocol traffic bypasses L7 application parsing and leaves no audit trail in the JSONL logs.

Shell Command Filtering & Obfuscation
- Static regex pattern matching on exec() commands is a coarse heuristic. Advanced command-line obfuscation (e.g., base64 encoding, quote-splitting like ba""sh, or alternative interpreters) can theoretically evade static regex rules.

Asynchronous Teardown & Successive-Call Race Window
- When a policy violation is detected, container termination is triggered asynchronously via the Docker daemon. A rapid or multi-threaded agent could theoretically issue a successive network request or command during the fractional-second window before docker kill fully reaps the container process.

- Note inspect-docker-auditor mitigates this at the framework level by immediately cancelling active Inspect AI exec() tasks the moment a violation occurs, while stateless L7 proxy rules continue independently blocking subsequent HTTP flows until the container is destroyed.

Encrypted Tunnels & DoH

- DNS-over-HTTPS (DoH) or custom encrypted protocols can sometimes bypass standard proxy inspection or obscure domain visibility.

Environment Visibility & Eval-Awareness

- The agent process can inspect its own environment variables (HTTP_PROXY), meaning it can become explicitly aware that it is being routed through an audited proxy gateway. This introduces a potential eval-awareness vector where sophisticated models may alter their strategy based on the presence of monitoring infrastructure.

Kernel & Container Escapes

- Vulnerabilities exploiting the underlying Linux kernel or container runtime isolation boundaries fall outside the scope of user-space proxy enforcement.
