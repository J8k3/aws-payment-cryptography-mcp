"""
API-surface drift tests.

Two jobs:

1. Typo guard — every boto3 method the tool layer calls must be a real operation on
   the corresponding service model. A misspelled `client().get_ky(...)` would otherwise
   only surface at runtime, as a MagicMock in tests happily accepts any attribute.

2. Drift detector — the set of operations we deliberately do not implement is written
   down. When AWS adds a new operation, this test fails and forces a decision instead
   of the addition going unnoticed.

That second job is the point. The UnionPay session-key-derivation release (2026-07-15)
and the Multi-Party Approval operations (2026-04-30) both sat unnoticed for months
because nothing in CI watched the service model.

When this test fails because AWS shipped something new, either implement the operation
or add it to the KNOWN_UNIMPLEMENTED set below with a reason.
"""

import re
from pathlib import Path

import botocore.session
import pytest

SRC = Path(__file__).parent.parent / "src" / "apc_agent"

# Operations we knowingly do not expose, and why.
KNOWN_UNIMPLEMENTED = {
    "payment-cryptography": set(),
    "payment-cryptography-data": set(),
}


def _pascal_to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _called_methods(filename: str) -> set[str]:
    """Every `client().<method>` referenced in a tool module."""
    source = (SRC / filename).read_text()
    return set(re.findall(r"client\(\)\.([a-z_][a-z0-9_]*)", source))


def _service_operations(service: str) -> set[str]:
    model = botocore.session.get_session().get_service_model(service)
    return set(model.operation_names)


CASES = [
    ("payment-cryptography", "control_plane.py"),
    ("payment-cryptography-data", "data_plane.py"),
]


@pytest.mark.parametrize("service,module", CASES)
def test_every_called_method_is_a_real_operation(service, module):
    valid = {_pascal_to_snake(op) for op in _service_operations(service)}
    called = _called_methods(module)
    unknown = called - valid
    assert not unknown, (
        f"{module} calls boto3 methods that do not exist on {service}: "
        f"{sorted(unknown)}. Check for a typo or a renamed operation."
    )


@pytest.mark.parametrize("service,module", CASES)
def test_no_unaccounted_operations(service, module):
    """
    Every operation is either implemented or explicitly listed as unimplemented.

    A failure here usually means AWS shipped a new operation. Implement it, or add it
    to KNOWN_UNIMPLEMENTED with a reason.
    """
    all_ops = _service_operations(service)
    implemented = {op for op in all_ops if _pascal_to_snake(op) in _called_methods(module)}
    unaccounted = all_ops - implemented - KNOWN_UNIMPLEMENTED[service]
    assert not unaccounted, (
        f"{service} has operations that are neither implemented in {module} nor listed "
        f"in KNOWN_UNIMPLEMENTED: {sorted(unaccounted)}. If AWS added these, decide "
        f"whether to implement them; otherwise record why they are skipped."
    )


@pytest.mark.parametrize("service,module", CASES)
def test_known_unimplemented_entries_still_exist(service, module):
    """Stop KNOWN_UNIMPLEMENTED from rotting: every entry must be a real operation."""
    stale = KNOWN_UNIMPLEMENTED[service] - _service_operations(service)
    assert not stale, (
        f"KNOWN_UNIMPLEMENTED[{service!r}] lists operations that no longer exist: "
        f"{sorted(stale)}. Remove them."
    )


@pytest.mark.parametrize("service,module", CASES)
def test_known_unimplemented_are_not_actually_implemented(service, module):
    """If an operation gets implemented, it must come off the skip list."""
    called = _called_methods(module)
    contradictions = {op for op in KNOWN_UNIMPLEMENTED[service] if _pascal_to_snake(op) in called}
    assert not contradictions, (
        f"These are implemented in {module} but still listed as unimplemented: "
        f"{sorted(contradictions)}. Remove them from KNOWN_UNIMPLEMENTED."
    )


# Input members we knowingly do not expose on a tool, and why.
#
# Everything else must be passed. A missing entry here means either a new AWS parameter
# went unnoticed, or a parameter name is wrong — the failure mode that left export_key
# broken from the service launch in 2023 until 2026-08-23. MagicMock-based tests cannot
# catch a wrong parameter name, because a mock accepts any keyword argument.
UNEXPOSED_PARAMETERS = {
    "payment-cryptography": {
        # Alias management is exposed through the dedicated alias tools.
        "CreateKey": set(),
        "ExportKey": set(),
        "GetParametersForImport": set(),
        "GetParametersForExport": set(),
    },
    "payment-cryptography-data": {},
}



def _passes_member(body: str, member: str) -> bool:
    """
    True if the tool body sends `member` to boto3.

    Both call styles in this codebase count: a quoted dict key (params["Member"] = ...)
    and a direct keyword argument (Member=value).
    """
    return bool(
        re.search(rf'"{re.escape(member)}"', body)
        or re.search(rf'\b{re.escape(member)}\s*=', body)
    )


def _tool_body(module: str, operation: str) -> str:
    """Source of the tool that calls `operation`, from its def down to the boto3 call."""
    source = (SRC / module).read_text()
    call = f"client().{_pascal_to_snake(operation)}"
    at = source.find(call)
    assert at != -1, f"{operation} is not called in {module}"
    start = source.rfind("    @mcp.tool()", 0, at)
    # Params may be built before the call (params dict) or passed after it as inline
    # kwargs, so the body runs to the start of the next tool.
    nxt = source.find("    @mcp.tool()", at)
    return source[start:nxt if nxt != -1 else len(source)]


@pytest.mark.parametrize("service,module", CASES)
def test_every_input_member_is_passed_or_explicitly_unexposed(service, module):
    """
    Catch parameter-level drift: new members added to operations we already implement.

    The operation-level tests above cannot see this. AWS added ReuseLastGeneratedToken to
    GetParametersForImport/Export on 2026-04-03 without adding any operation, so nothing
    flagged it.
    """
    model = botocore.session.get_session().get_service_model(service)
    problems = []
    for operation in sorted(model.operation_names):
        method = _pascal_to_snake(operation)
        if method not in _called_methods(module):
            continue
        shape = model.operation_model(operation).input_shape
        if shape is None:
            continue
        body = _tool_body(module, operation)
        allowed = UNEXPOSED_PARAMETERS.get(service, {}).get(operation, set())
        missing = {m for m in shape.members if not _passes_member(body, m)} - allowed
        if missing:
            required = set(shape.required_members) & missing
            problems.append(
                f"{operation}: {sorted(missing)}"
                + (f"  <-- REQUIRED: {sorted(required)}" if required else "")
            )
    assert not problems, (
        "Input members neither passed nor listed in UNEXPOSED_PARAMETERS:\n  "
        + "\n  ".join(problems)
        + "\n\nIf AWS added a parameter, expose it or record why not. If a name looks "
          "wrong, check it against the service model — a wrong name fails at runtime but "
          "passes every MagicMock test."
    )


def assert_params_valid(service: str, operation: str, params: dict) -> None:
    """
    Validate real call kwargs against the real service model.

    This is what a MagicMock cannot do. Use it in tool tests that capture call_args so the
    assertion is against AWS's contract rather than against the code's own behaviour.
    """
    from botocore.validate import ParamValidator

    model = botocore.session.get_session().get_service_model(service)
    report = ParamValidator().validate(params, model.operation_model(operation).input_shape)
    assert not report.has_errors(), f"{operation} params rejected by the service model:\n{report.generate_report()}"


@pytest.mark.parametrize("service,module", CASES)
def test_unexposed_parameter_entries_still_exist(service, module):
    """Stop UNEXPOSED_PARAMETERS from rotting."""
    model = botocore.session.get_session().get_service_model(service)
    stale = []
    for operation, members in UNEXPOSED_PARAMETERS.get(service, {}).items():
        if operation not in model.operation_names:
            stale.append(f"{operation} (operation gone)")
            continue
        shape = model.operation_model(operation).input_shape
        gone = members - set(shape.members or {})
        if gone:
            stale.append(f"{operation}: {sorted(gone)}")
    assert not stale, f"UNEXPOSED_PARAMETERS lists things that no longer exist: {stale}"
