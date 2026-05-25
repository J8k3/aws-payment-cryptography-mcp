"""
pytest configuration — applies moto AWS mock to every non-integration test.

Tests marked @pytest.mark.integration require real AWS credentials and are
skipped unless INTEGRATION_TESTS=true is set in the environment. All other
tests run under moto regardless of whether real credentials exist.
"""

import os

import pytest
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture(autouse=True)
def moto_aws_mock(request):
    if request.node.get_closest_marker("integration"):
        yield
    else:
        with mock_aws():
            yield
