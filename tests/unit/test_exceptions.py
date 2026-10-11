import pytest

from inspect_docker_auditor.exceptions import AuditorPermissionError


@pytest.mark.unit
def test_auditor_permission_error_with_violation_type() -> None:
    """
    Verify metadata assignment and formatted string output when violation_type is
    present.
    """
    err = AuditorPermissionError("Outbound request blocked", violation_type="network")

    assert err.violation_type == "network"
    assert str(err) == "[NETWORK] Outbound request blocked"


@pytest.mark.unit
def test_auditor_permission_error_default():
    """Verify fallback behavior when violation_type is omitted."""
    err = AuditorPermissionError("Access denied")

    assert err.violation_type is None
    assert str(err) == "Access denied"


@pytest.mark.unit
def test_auditor_permission_error_inheritance():
    """
    Verify backward compatibility: standard PermissionError handlers must catch this
    error.
    """
    with pytest.raises(PermissionError) as exc_info:
        raise AuditorPermissionError(
            "Blacklisted command executed", violation_type="command"
        )

    # Verify attributes survive being caught as a standard PermissionError
    caught_err = exc_info.value
    assert isinstance(caught_err, AuditorPermissionError)
    assert caught_err.violation_type == "command"
    assert "[COMMAND]" in str(caught_err)
