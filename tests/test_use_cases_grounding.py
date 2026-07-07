"""
Grounding tests: the use-cases catalog vs the installed botocore service model.

The catalog (aws-payment-cryptography-data-plane-use-cases.json) makes
machine-checkable claims — which operations exist, their endpoints, and which
request fields are required. The botocore service model for
payment-cryptography-data is generated from the same source AWS generates the
service from, so any disagreement is either a transcription error in the
catalog or the service moving (an operation added/changed in a newer SDK).
Either way it must surface as a named failure, not wait to be noticed.

This is the mechanism that would have caught the issue #15 field-list error
(PrimaryAccountNumber/PanSequenceNumber listed as top-level required fields
when they are members inside the SessionKeyDerivationAttributes union).

No AWS credentials required — the service model ships inside botocore.
"""

import json
from pathlib import Path

import botocore.session
import pytest

_CATALOG_PATH = Path(__file__).parent.parent / "aws-payment-cryptography-data-plane-use-cases.json"


@pytest.fixture(scope="module")
def catalog():
    return json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def service_model():
    return botocore.session.get_session().get_service_model("payment-cryptography-data")


@pytest.fixture(scope="module")
def catalog_ops(catalog):
    return {op["name"]: op for op in catalog["operations"]}


class TestCatalogMatchesSdkModel:
    def test_every_catalog_operation_exists_in_sdk_model(self, catalog_ops, service_model):
        phantom = sorted(set(catalog_ops) - set(service_model.operation_names))
        assert not phantom, (
            f"Catalog claims operations the SDK model does not define: {phantom}. "
            "Either the catalog invented them or the installed botocore is too old "
            "to know them — pin the intended minimum botocore version if the latter."
        )

    def test_catalog_is_complete_vs_sdk_model(self, catalog_ops, service_model):
        missing = sorted(set(service_model.operation_names) - set(catalog_ops))
        assert not missing, (
            f"The SDK model defines data-plane operations the catalog does not "
            f"cover: {missing}. The catalog claims to enumerate all documented "
            "operations — add entries for these (this is how "
            "GenerateAuthRequestCryptogram went unnoticed until issue #15)."
        )

    def test_required_fields_match_sdk_model(self, catalog_ops, service_model):
        mismatches = {}
        for name, op in catalog_ops.items():
            if name not in service_model.operation_names:
                continue  # reported by the existence test
            model_required = set(
                service_model.operation_model(name).input_shape.required_members
            )
            catalog_required = set(op.get("required_fields", []))
            if model_required != catalog_required:
                mismatches[name] = {
                    "catalog_only": sorted(catalog_required - model_required),
                    "model_only": sorted(model_required - catalog_required),
                }
        assert not mismatches, (
            f"required_fields disagree with the SDK model: {mismatches}. "
            "catalog_only fields are usually transcription errors (e.g. union "
            "members promoted to top level); model_only fields mean the request "
            "shape gained a required member."
        )

    def test_endpoints_match_sdk_model(self, catalog_ops, service_model):
        mismatches = {}
        for name, op in catalog_ops.items():
            if name not in service_model.operation_names or "endpoint" not in op:
                continue
            http = service_model.operation_model(name).http
            model_endpoint = f"{http['method']} {http['requestUri']}"
            if op["endpoint"] != model_endpoint:
                mismatches[name] = {"catalog": op["endpoint"], "model": model_endpoint}
        assert not mismatches, f"endpoint strings disagree with the SDK model: {mismatches}"
