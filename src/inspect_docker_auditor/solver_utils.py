from inspect_ai.model import ChatMessageSystem
from inspect_ai.solver import Generate, Solver, TaskState, solver

from .exceptions import AuditorPermissionError


def auditor_solver(
    target_solver: Solver,
    *,
    mark_completed: bool = True,
) -> Solver:
    """
    Higher-order solver wrapper that catches policy violations during trajectory
    execution.

    Prevents the evaluation task from crashing when a sandbox/network policy is
    breached.
    """

    @solver
    def wrapper() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            try:
                return await target_solver(state, generate)
            except AuditorPermissionError as err:
                # Capture violation context without crashing the runner
                state.store.set("security_violation", str(err))
                state.messages.append(
                    ChatMessageSystem(
                        content=(
                            f"[Execution Stopped]: Sandbox policy violation - {err}"
                        )
                    )
                )
                if mark_completed:
                    state.completed = True
                return state

        return solve

    return wrapper()
