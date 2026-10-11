from inspect_ai import Task, eval, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox


@solver
def proxy_discovery_solver():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        python_cmd = """
        import urllib.request
        try:
            resp = urllib.request.urlopen('http://example.com', timeout=5)
            print(resp.status)
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
def audited_discovery_task() -> Task:
    return Task(
        dataset=MemoryDataset([Sample(input="Run proxy test", target="200")]),
        plan=[proxy_discovery_solver()],
        # Built-in Inspect scorer that checks if sample.target is inside
        # state.output.completion
        scorer=includes(),
        sandbox=("docker_audited", "compose.yaml"),
    )


if __name__ == "__main__":
    eval(audited_discovery_task())
