from pathlib import Path

import pytest
from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox

# Define test samples with clean IDs for pytest output
ALLOWED_TEST_SAMPLES = [
    Sample(
        id="allowed_command",
        input="echo ALLOWED_COMMAND",
        target="EXECUTED: ALLOWED_COMMAND",
    ),
]

BLOCK_TEST_SAMPLES = [
    Sample(
        id="blocked_passwd",
        input="cat /etc/passwd",
        target="BLOCKED",
    )
]


@solver
def command_exec_solver():
    """Executes the string provided in sample input and catches policy blocks."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        cmd = state.input_text.split()

        try:
            res = await sandbox().exec(cmd)
            output_str = f"EXECUTED: {res.stdout.strip()}"
        except PermissionError as e:
            output_str = f"BLOCKED: {e}"
        except Exception as e:
            output_str = f"FAILED: {type(e).__name__} - {e}"

        state.output.completion = output_str
        print(f"\n[SOLVER OUTPUT]: {output_str}")
        return state

    return solve


@pytest.mark.integration
@pytest.mark.parametrize("sample", ALLOWED_TEST_SAMPLES, ids=lambda s: s.id)
def test_audited_solver_sample_pass_command(
    sample: Sample, sample_config_yaml: Path, tmp_path: Path
):
    """
    Executes the solver against a single sample and maps the result directly to Pytest.
    """

    # Create a 1-sample task for this specific test run
    task = Task(
        dataset=MemoryDataset([sample]),
        plan=[command_exec_solver()],
        sandbox=("docker_audited", str(sample_config_yaml.resolve())),
        scorer=includes(),
    )

    # Evaluate the single sample
    logs = inspect_eval(task, log_dir=str(tmp_path / "logs"))
    sample_result = logs[0].samples[0]

    # Direct pytest assertion on this specific sample's solver outcome
    score = sample_result.scores["includes"]
    actual_output = (
        sample_result.output.completion if sample_result.output else "NO OUTPUT"
    )

    assert score.as_str() == "C", (
        f"Solver failed on input: '{sample.input}'\n"
        f"Expected target : {sample.target}\n"
        f"Actual completion: {actual_output}"
    )


@pytest.mark.integration
@pytest.mark.parametrize("sample", BLOCK_TEST_SAMPLES, ids=lambda s: s.id)
def test_audited_solver_sample_block_command(
    sample: Sample, sample_terminate_on_violation_config_yaml: Path, tmp_path: Path
):
    """
    Executes the solver against a single sample and maps the result directly to Pytest.
    """

    task = Task(
        dataset=MemoryDataset([sample]),
        plan=[command_exec_solver()],
        sandbox=(
            "docker_audited",
            str(sample_terminate_on_violation_config_yaml.resolve()),
        ),
        scorer=includes(),
    )

    # Evaluate the single sample
    logs = inspect_eval(task, log_dir=str(tmp_path / "logs"))
    sample_result = logs[0].samples[0]

    # Direct pytest assertion on this specific sample's solver outcome
    score = sample_result.scores["includes"]
    actual_output = (
        sample_result.output.completion if sample_result.output else "NO OUTPUT"
    )

    assert score.as_str() == "C", (
        f"Solver failed on input: '{sample.input}'\n"
        f"Expected target : {sample.target}\n"
        f"Actual completion: {actual_output}"
    )
