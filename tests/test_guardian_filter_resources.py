"""Tests for Guardian.filter_resources() method.

Covers:
- Filter tools returns only allowed resources.
- Filter datasets using ResourceType.DATASET.
- Returns FilteredResources with .allowed and .denied lists.
- Falls back to allow-all when no PolicyEvaluator is configured.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from navigator_auth.abac.guardian import Guardian
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.policies.evaluator import FilteredResources


class FakePDP:
    """Minimal PDP stub for Guardian tests."""

    def __init__(self, evaluator=None):
        self._evaluator = evaluator


def _make_request(authenticated: bool = True):
    """Create a minimal mock request."""
    req = MagicMock()
    req.get.return_value = authenticated
    req.remote = "127.0.0.1"
    req.method = "GET"
    req.headers = {}
    req.path_qs = "/"
    req.path = "/"
    req.rel_url = "/"
    req.is_authenticated = authenticated
    return req


def _make_guardian_with_evaluator(resources, action, expected_allowed):
    """Build a Guardian whose PolicyEvaluator filters to expected_allowed."""
    from navigator_auth.abac.policies.evaluator import PolicyEvaluator

    evaluator = MagicMock(spec=PolicyEvaluator)
    denied = [r for r in resources if r not in expected_allowed]
    evaluator.filter_resources.return_value = FilteredResources(
        allowed=list(expected_allowed),
        denied=denied,
    )
    pdp = FakePDP(evaluator=evaluator)
    return Guardian(pdp=pdp)


@pytest.mark.asyncio
async def test_filter_resources_returns_filtered_resources():
    """filter_resources() returns FilteredResources with allowed/denied."""
    all_tools = ["search", "admin_delete", "public_read"]
    guardian = _make_guardian_with_evaluator(
        all_tools, "tool:execute", ["search", "public_read"]
    )

    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={"groups": ["users"]})
    user = MagicMock()

    with patch.object(guardian, "is_authenticated"), \
         patch.object(guardian, "get_user", new=AsyncMock(return_value=(session, user))):
        result = await guardian.filter_resources(
            resources=all_tools,
            request=_make_request(),
            resource_type=ResourceType.TOOL,
            action="tool:execute",
        )

    assert "search" in result.allowed
    assert "public_read" in result.allowed
    assert "admin_delete" in result.denied


@pytest.mark.asyncio
async def test_filter_resources_dataset_type():
    """filter_resources() works for ResourceType.DATASET."""
    datasets = ["sales_data", "hr_confidential"]
    guardian = _make_guardian_with_evaluator(
        datasets, "dataset:query", ["sales_data"]
    )

    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={"groups": ["sales"]})
    user = MagicMock()

    with patch.object(guardian, "is_authenticated"), \
         patch.object(guardian, "get_user", new=AsyncMock(return_value=(session, user))):
        result = await guardian.filter_resources(
            resources=datasets,
            request=_make_request(),
            resource_type=ResourceType.DATASET,
            action="dataset:query",
        )

    assert "sales_data" in result.allowed
    assert "hr_confidential" in result.denied


@pytest.mark.asyncio
async def test_filter_resources_no_evaluator_allows_all():
    """When no PolicyEvaluator on PDP, all resources are allowed."""
    pdp = FakePDP(evaluator=None)
    guardian = Guardian(pdp=pdp)

    resources = ["tool_a", "tool_b"]
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={})
    user = MagicMock()

    with patch.object(guardian, "is_authenticated"), \
         patch.object(guardian, "get_user", new=AsyncMock(return_value=(session, user))):
        result = await guardian.filter_resources(
            resources=resources,
            request=_make_request(),
            resource_type=ResourceType.TOOL,
            action="tool:execute",
        )

    assert set(result.allowed) == set(resources)
    assert result.denied == []


@pytest.mark.asyncio
async def test_filter_resources_empty_list():
    """filter_resources() on empty list returns empty FilteredResources."""
    guardian = _make_guardian_with_evaluator([], "tool:execute", [])

    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={})
    user = MagicMock()

    with patch.object(guardian, "is_authenticated"), \
         patch.object(guardian, "get_user", new=AsyncMock(return_value=(session, user))):
        result = await guardian.filter_resources(
            resources=[],
            request=_make_request(),
            resource_type=ResourceType.TOOL,
            action="tool:execute",
        )

    assert result.allowed == []
    assert result.denied == []
