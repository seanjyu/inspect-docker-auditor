class AuditorPermissionError(PermissionError):
    """Single auditor error extended with structured metadata."""

    def __init__(self, message: str, *, violation_type: str | None = None):
        super().__init__(message)
        self.violation_type = violation_type

    def __str__(self) -> str:
        if self.violation_type:
            return f"[{self.violation_type.upper()}] {super().__str__()}"
        return super().__str__()
