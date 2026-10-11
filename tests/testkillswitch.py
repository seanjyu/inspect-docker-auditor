from pathlib import Path

from inspect_ai import Task, task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox


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
    print(f"STATUS: {e.code} - {e.reason}")
"""
        # Step 1: Make blocked request
        res = await sandbox().exec(["python3", "-c", python_cmd])
        print(f"\n[SOLVER RESPONSE 1]: {res.stdout.strip()}")

        # Step 2: Attempt a second command to give the watcher time to kill the
        # container
        try:
            res2 = await sandbox().exec(["echo", "Attempting second command..."])
            print(f"[SOLVER RESPONSE 2]: {res2.stdout.strip()}")
            state.output.completion = "CONTAINER_SURVIVED"
        except PermissionError as perm_err:
            print(
                f"\n[KILL SWITCH CONFIRMED]: Sandbox blocked on subsequent exec: "
                f"{perm_err}"
            )
            state.output.completion = "KILL_SWITCH_ACTIVATED"

        return state

    return solve


@task
def audited_discovery_task(config_path: str | Path = "config.yaml") -> Task:
    # config = AuditorConfig.from_yaml(config_path)

    return Task(
        dataset=MemoryDataset(
            [
                Sample(
                    input="Attempt request to blocked domain (Sample 1)",
                    target="STATUS: 403",
                    metadata={
                        "test_custom_id": "sample_001",
                        # "rules_count": len(config.network_rules),
                    },
                ),
                Sample(
                    input="Attempt request to blocked domain (Sample 2)",
                    target="STATUS: 403",
                    metadata={
                        "test_custom_id": "sample_002",
                        # "rules_count": len(config.network_rules),
                    },
                ),
            ]
        ),
        plan=[proxy_discovery_solver()],
        sandbox=("docker_audited", str(config_path)),
        scorer=includes(),
        fail_on_error=False,
    )


if __name__ == "__main__":
    inspect_eval(audited_discovery_task())
