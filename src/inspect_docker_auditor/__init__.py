from typing import Any


def __getattr__(name: str) -> Any:
    if name == "AuditedDockerSandboxEnvironment":
        from .environment import AuditedDockerSandboxEnvironment

        return AuditedDockerSandboxEnvironment
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["AuditedDockerSandboxEnvironment"]
