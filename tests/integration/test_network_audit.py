from pathlib import Path

import pytest
from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox

# Allowed network egress tests
ALLOWED_NETWORK_SAMPLES = [
    Sample(
        id="allowed_http_example",
        input="http://example.com",
        target="STATUS: 200",
    ),
    Sample(
        id="allowed_https_python",
        input="https://pypi.org",
        target="STATUS: 200",
    ),
]

# Blocked egress / MITM policy violation tests
BLOCKED_NETWORK_SAMPLES = [
    Sample(
        id="blocked_domain_badsite",
        input="http://badsite.org",
        target="STATUS: 403 - Forbidden",
    ),
    Sample(
        id="blocked_cloud_metadata_ssrf",
        input="http://169.254.169.254/latest/meta-data/",
        target="STATUS: 403 - Forbidden",
    ),
]


@solver
def network_request_solver(timeout: int = 5):
    """
    Executes an HTTP request inside the sandbox to state.input_text and returns the
    status.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        url = state.input_text.strip()

        # Dynamic python script that tests state.input_text
        python_cmd = f"""
import urllib.request
import urllib.error

url = {repr(url)}
try:
    req = urllib.request.Request(url, headers={{"User-Agent": "InspectAI-Auditor/1.0"}})
    with urllib.request.urlopen(req, timeout={timeout}) as resp:
        print(f"STATUS: {{resp.status}}")
except urllib.error.HTTPError as e:
    # mitmproxy responds with 403 when blocked by network policy engine
    print(f"STATUS: {{e.code}} - {{e.reason}}")
except Exception as e:
    print(f"FAILED: {{type(e).__name__}} - {{e}}")
"""
        res = await sandbox().exec(["python3", "-c", python_cmd])

        output_str = res.stdout.strip()
        if not output_str and res.stderr:
            output_str = f"FAILED: {res.stderr.strip()}"

        state.output.completion = output_str
        print(f"\n[NETWORK SOLVER] [{state.sample_id}]: {output_str}")
        return state

    return solve


# Combine allowed and blocked samples for full test coverage
ALL_NETWORK_SAMPLES = ALLOWED_NETWORK_SAMPLES + BLOCKED_NETWORK_SAMPLES


@pytest.mark.integration
@pytest.mark.parametrize("sample", ALL_NETWORK_SAMPLES, ids=lambda s: s.id)
def test_audited_network_egress_sample(
    sample: Sample, sample_config_yaml: Path, tmp_path: Path
):
    """
    Executes network_request_solver against network test samples and asserts policy
    outcomes.
    """

    # Create a 1-sample task for this specific test iteration
    task = Task(
        dataset=MemoryDataset([sample]),
        plan=[network_request_solver()],
        sandbox=("docker_audited", str(sample_config_yaml.resolve())),
        scorer=includes(),
    )

    # Evaluate the single sample
    logs = inspect_eval(task, log_dir=str(tmp_path / "logs"))
    sample_result = logs[0].samples[0]

    # Verify scorer evaluation
    score = sample_result.scores["includes"]
    actual_output = (
        sample_result.output.completion if sample_result.output else "NO OUTPUT"
    )

    assert score.as_str() == "C", (
        f"Network egress test failed for sample ID: '{sample.id}'\n"
        f"URL tested       : '{sample.input}'\n"
        f"Expected pattern : '{sample.target}'\n"
        f"Actual output    : '{actual_output}'"
    )
