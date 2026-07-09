"""Tests for YAMLStorage field mapping and PDP double-load prevention.

Reproduces the bug where YAMLStorage._parse_file() produced dicts with
classic-format keys (``resource`` singular, flat ``groups``/``subject``)
while setting ``policy_type='resource'``, causing PolicyAdapter._adapt_resource()
to create ResourcePolicy objects with empty resources and subjects — turning
any DENY policy into a deny-all.
"""
import asyncio
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, PolicyLoader
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies import PolicyEffect


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_POLICY_YAML = textwrap.dedent("""\
    version: "1.0"
    defaults:
      effect: deny
    policies:
      - name: allow_superuser_all
        effect: allow
        resources:
          - "uri:/api/v1/.*"
          - "uri:/api/v2/.*"
        actions:
          - "uri:read"
          - "uri:write"
        subjects:
          groups:
            - superuser
          users:
            - admin@example.com
        priority: 100
        enforcing: false

      - name: deny_guests_write
        effect: deny
        resources:
          - "uri:/api/v1/.*"
        actions:
          - "uri:write"
        subjects:
          groups:
            - guest
        priority: 50
        enforcing: true
""")


@pytest.fixture
def policy_dir(tmp_path):
    """Write sample YAML to a temp directory and return its path."""
    (tmp_path / "main.yaml").write_text(SAMPLE_POLICY_YAML)
    return tmp_path


# ---------------------------------------------------------------------------
# Fix C — _parse_file produces correct keys for policy_type='resource'
# ---------------------------------------------------------------------------

class TestParseFileFieldMapping:
    """Verify _parse_file output matches what PolicyAdapter expects."""

    def test_resource_type_uses_plural_resources_key(self, policy_dir):
        """policy_type='resource' dicts must use 'resources' (plural)."""
        dicts = YAMLStorage._parse_file(policy_dir / "main.yaml")
        for d in dicts:
            if d['policy_type'] == 'resource':
                assert 'resources' in d, (
                    f"Policy '{d['name']}' has policy_type='resource' but "
                    f"uses 'resource' (singular) instead of 'resources' (plural)"
                )
                assert 'resource' not in d

    def test_resource_type_uses_structured_subjects(self, policy_dir):
        """policy_type='resource' dicts must use structured 'subjects' dict."""
        dicts = YAMLStorage._parse_file(policy_dir / "main.yaml")
        for d in dicts:
            if d['policy_type'] == 'resource':
                assert 'subjects' in d, (
                    f"Policy '{d['name']}' missing structured 'subjects'"
                )
                assert isinstance(d['subjects'], dict)
                assert 'groups' not in d, "Should not have flat 'groups' key"
                assert 'subject' not in d, "Should not have flat 'subject' key"

    def test_resource_type_subjects_preserve_structure(self, policy_dir):
        """Subjects dict should preserve groups and users from YAML."""
        dicts = YAMLStorage._parse_file(policy_dir / "main.yaml")
        allow_policy = next(d for d in dicts if d['name'] == 'allow_superuser_all')
        assert allow_policy['subjects']['groups'] == ['superuser']
        assert allow_policy['subjects']['users'] == ['admin@example.com']

    def test_resource_type_resources_are_preserved(self, policy_dir):
        """Resources list should come through intact."""
        dicts = YAMLStorage._parse_file(policy_dir / "main.yaml")
        allow_policy = next(d for d in dicts if d['name'] == 'allow_superuser_all')
        assert allow_policy['resources'] == ['uri:/api/v1/.*', 'uri:/api/v2/.*']

    def test_classic_type_uses_singular_resource_key(self, tmp_path):
        """policy_type='policy' dicts must use 'resource' (singular)."""
        yaml_content = textwrap.dedent("""\
            version: "1.0"
            policies:
              - name: classic_policy
                policy_type: policy
                effect: allow
                resources:
                  - "uri:/api/v1/test"
                actions:
                  - "GET"
                subjects:
                  groups:
                    - admin
                  users:
                    - bob@example.com
        """)
        (tmp_path / "classic.yaml").write_text(yaml_content)
        dicts = YAMLStorage._parse_file(tmp_path / "classic.yaml")
        assert len(dicts) == 1
        d = dicts[0]
        assert d['policy_type'] == 'policy'
        assert 'resource' in d
        assert 'resources' not in d
        assert 'groups' in d
        assert 'subject' in d


# ---------------------------------------------------------------------------
# Fix C + A — PolicyAdapter produces valid ResourcePolicy from YAML dicts
# ---------------------------------------------------------------------------

class TestAdapterFromYAMLStorage:
    """Ensure PolicyAdapter correctly processes YAMLStorage output."""

    def test_adapt_resource_preserves_resources(self, policy_dir):
        """ResourcePolicy must have non-empty resources after adaptation."""
        dicts = YAMLStorage._parse_file(policy_dir / "main.yaml")
        policies, warnings = PolicyAdapter.adapt_batch(dicts)
        assert len(policies) >= 2

        allow_policy = next(p for p in policies if p.name == 'allow_superuser_all')
        assert len(allow_policy._resource_patterns) > 0, (
            "ResourcePolicy has no resource patterns — _adapt_resource "
            "could not find 'resources' key in the dict"
        )

    def test_adapt_resource_preserves_subjects(self, policy_dir):
        """ResourcePolicy must have non-empty subjects after adaptation."""
        dicts = YAMLStorage._parse_file(policy_dir / "main.yaml")
        policies, warnings = PolicyAdapter.adapt_batch(dicts)

        allow_policy = next(p for p in policies if p.name == 'allow_superuser_all')
        assert len(allow_policy._subjects.groups) > 0, (
            "ResourcePolicy has empty subject groups — _adapt_resource "
            "could not find structured 'subjects' key in the dict"
        )

    def test_deny_policy_not_deny_all(self, policy_dir):
        """A DENY policy with specific resources must NOT become deny-all."""
        dicts = YAMLStorage._parse_file(policy_dir / "main.yaml")
        policies, warnings = PolicyAdapter.adapt_batch(dicts)

        deny_policy = next(p for p in policies if p.name == 'deny_guests_write')
        assert len(deny_policy._resource_patterns) > 0, (
            "DENY policy has no resource patterns — it would deny everything"
        )
        assert len(deny_policy._subjects.groups) > 0, (
            "DENY policy has no subject restriction — it would deny everyone"
        )


# ---------------------------------------------------------------------------
# Fix B — PDP._load_policies skips when evaluator is pre-populated
# ---------------------------------------------------------------------------

class _FakeIndex:
    """Minimal PolicyIndex stand-in for tests that cannot build rs_pep."""

    def __init__(self):
        self._policies = []

    def add(self, policy):
        self._policies.append(policy)

    def finalize(self):
        pass

    def all(self):
        return list(self._policies)


def _make_fake_evaluator(policies=None):
    """Build a mock PolicyEvaluator that tracks load_policies calls."""
    ev = MagicMock()
    idx = _FakeIndex()
    if policies:
        for p in policies:
            idx.add(p)
    ev._index = idx
    ev.load_policies = MagicMock(side_effect=lambda ps: [idx.add(p) for p in ps])
    ev.swap_index = MagicMock()
    return ev


class TestPDPDoubleLoadPrevention:
    """PDP._load_policies must not re-load when evaluator is pre-populated."""

    @pytest.fixture
    def pre_loaded_evaluator(self, policy_dir):
        """A fake evaluator already populated with policies."""
        policies = PolicyLoader.load_from_directory(policy_dir)
        return _make_fake_evaluator(policies)

    def test_load_policies_skips_when_evaluator_has_policies(
        self, policy_dir, pre_loaded_evaluator
    ):
        from navigator_auth.abac.pdp import PDP

        yaml_storage = YAMLStorage(directory=str(policy_dir))
        pdp = PDP(storage=yaml_storage, evaluator=pre_loaded_evaluator)

        initial_count = len(pre_loaded_evaluator._index.all())
        assert initial_count > 0

        asyncio.get_event_loop().run_until_complete(pdp._load_policies())

        pre_loaded_evaluator.load_policies.assert_not_called()
        final_count = len(pre_loaded_evaluator._index.all())
        assert final_count == initial_count, (
            f"Evaluator policy count changed from {initial_count} to "
            f"{final_count} — _load_policies should have skipped"
        )

    def test_load_policies_proceeds_when_evaluator_is_empty(self, policy_dir):
        from navigator_auth.abac.pdp import PDP

        yaml_storage = YAMLStorage(directory=str(policy_dir))
        ev = _make_fake_evaluator()
        pdp = PDP(storage=yaml_storage, evaluator=ev)

        assert len(ev._index.all()) == 0
        asyncio.get_event_loop().run_until_complete(pdp._load_policies())
        ev.load_policies.assert_called()
        assert len(ev._index.all()) > 0, (
            "_load_policies should have loaded policies into empty evaluator"
        )

    def test_reload_policies_always_works(self, policy_dir, pre_loaded_evaluator):
        """reload_policies (hot-reload) must always refresh, even if pre-loaded."""
        from navigator_auth.abac.pdp import PDP

        yaml_storage = YAMLStorage(directory=str(policy_dir))
        pdp = PDP(storage=yaml_storage, evaluator=pre_loaded_evaluator)

        initial_count = len(pre_loaded_evaluator._index.all())
        new_count = asyncio.get_event_loop().run_until_complete(
            pdp.reload_policies()
        )
        pre_loaded_evaluator.swap_index.assert_called_once()
        assert new_count > 0, "reload_policies should have loaded policies"


# ---------------------------------------------------------------------------
# Integration: full round-trip matching PolicyLoader vs YAMLStorage+Adapter
# ---------------------------------------------------------------------------

class TestRoundTripConsistency:
    """Policies loaded via PolicyLoader and via YAMLStorage+Adapter must
    produce equivalent ResourcePolicy objects."""

    def test_both_paths_produce_same_resources(self, policy_dir):
        loader_policies = PolicyLoader.load_from_directory(policy_dir)

        yaml_storage = YAMLStorage(directory=str(policy_dir))
        dicts = asyncio.get_event_loop().run_until_complete(
            yaml_storage.load_policies()
        )
        adapter_policies, _ = PolicyAdapter.adapt_batch(dicts)

        loader_names = {p.name for p in loader_policies}
        adapter_names = {p.name for p in adapter_policies}
        assert loader_names == adapter_names, (
            f"Policy names differ: loader={loader_names}, adapter={adapter_names}"
        )

        for lp in loader_policies:
            ap = next(p for p in adapter_policies if p.name == lp.name)
            loader_resources = {
                f"{rp.resource_type}:{rp.pattern}"
                for rp in lp._resource_patterns
            }
            adapter_resources = {
                f"{rp.resource_type}:{rp.pattern}"
                for rp in ap._resource_patterns
            }
            assert loader_resources == adapter_resources, (
                f"Policy '{lp.name}' resource mismatch: "
                f"loader={loader_resources}, adapter={adapter_resources}"
            )
