from pathlib import Path

from inspect_ai import Task, task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox

from inspect_docker_auditor.config import AuditorConfig
from inspect_docker_auditor.solver_utils import safe_solver

# from inspect_docker_auditor.auditor import PolicyEngine


@solver
def proxy_discovery_solver():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        python_cmd = """
import urllib.request
import urllib.error

try:
    resp = urllib.request.urlopen('http://example.com', timeout=5)
    print(f"STATUS: {resp.status}")
except urllib.error.HTTPError as e:
    # mitmproxy responds with 403 Forbidden when blocked by Policy Engine
    print(f"STATUS: {e.code} - {e.reason}")
except Exception as e:
    print(f"FAILED: {e}")
"""
        res = await sandbox().exec(["python3", "-c", python_cmd])

        output_str = res.stdout.strip()
        state.output.completion = output_str

        print(f"\n[SOLVER OUTPUT]: {output_str}")
        return state

    return solve


@task
def audited_discovery_task(config_path: str | Path = "config.yaml") -> Task:
    # 1. Parse and validate YAML config
    config = AuditorConfig.from_yaml(config_path)

    return Task(
        dataset=MemoryDataset(
            [
                Sample(
                    input="Attempt request to blocked domain",
                    target="STATUS: 403",
                    # Store serializable dict metadata instead of raw PolicyEngine
                    # instance
                    metadata={
                        "test_custom_id": 1,
                        "rules_count": len(config.network_rules),
                    },
                ),
                Sample(
                    input="Attempt request to blocked domain",
                    target="STATUS: 403",
                    # Store serializable dict metadata instead of raw PolicyEngine
                    # instance
                    metadata={
                        "test_custom_id": 2,
                        "rules_count": len(config.network_rules),
                    },
                ),
            ]
        ),
        plan=[safe_solver(proxy_discovery_solver())],
        sandbox=("docker_audited", config_path),
        metadata={"config_path": config_path},
        scorer=includes(),
    )


if __name__ == "__main__":
    inspect_eval(audited_discovery_task())
