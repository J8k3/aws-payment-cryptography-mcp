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
