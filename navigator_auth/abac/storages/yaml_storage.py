"""
YAML-based Policy Storage.

Loads policies from YAML files in a configurable directory.
Supports hot-reload and graceful error handling.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import yaml

from .abstract import AbstractStorage

logger = logging.getLogger(__name__)


class YAMLStorage(AbstractStorage):
    """Load policies from YAML files in a directory.

    Scans the given directory for ``.yaml`` and ``.yml`` files, parses them
    into policy dicts compatible with PDP loading, and supports hot-reload.

    Args:
        directory: Path to the directory containing YAML policy files.
    """

    def __init__(self, directory: str | Path):
        self._directory = Path(directory)
        self._policies: list[dict] = []
        self._loaded = False

    async def load_policies(self) -> list[dict]:
        """Load all policies from YAML files in the directory.

        Returns:
            List of policy dicts compatible with PDP._load_policies format.
            Each dict contains: name, effect, resource, actions, conditions,
            groups, context, environment, priority, enforcing, policy_type, etc.
        """
        self._policies = []
        if not self._directory.exists():
            logger.warning(
                f"YAML policy directory does not exist: {self._directory}"
            )
            return self._policies

        for path in sorted(self._directory.iterdir()):
            if path.suffix not in ('.yaml', '.yml'):
                continue
            try:
                policies = self._parse_file(path)
                self._policies.extend(policies)
                logger.debug(f"Loaded {len(policies)} policies from {path.name}")
            except Exception as exc:
                logger.error(f"Failed to load YAML policy file {path}: {exc}")
                continue

        self._loaded = True
        logger.info(
            f"YAMLStorage loaded {len(self._policies)} policies "
            f"from {self._directory}"
        )
        return self._policies

    async def save_policy(self, policy: dict) -> None:
        """Save a policy dict to a new YAML file.

        Args:
            policy: Policy dict to persist.
        """
        self._directory.mkdir(parents=True, exist_ok=True)
        name = policy.get('name', 'unnamed')
        filename = f"{name}.yaml"
        path = self._directory / filename

        # Wrap in standard YAML policy format
        data = {
            'version': '1.0',
            'policies': [policy],
        }
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        logger.info(f"Saved policy '{name}' to {path}")

    async def reload(self) -> list[dict]:
        """Reload all policies (hot-reload support).

        Returns:
            Freshly loaded list of policy dicts.
        """
        return await self.load_policies()

    async def close(self) -> None:
        """No-op for file-based storage."""
        pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_file(path: Path) -> list[dict]:
        """Parse a YAML policy file into PDP-compatible policy dicts.

        The YAML schema supports:
        - ``version``: schema version (currently "1.0")
        - ``defaults``: default values (e.g. ``effect: deny``)
        - ``policies``: list of policy definitions

        Each policy is converted into a dict compatible with
        ``PDP._load_policies``.
        """
        with open(path, 'r') as f:
            data = yaml.safe_load(f)

        if data is None:
            return []

        policies = []
        default_effect = data.get('defaults', {}).get('effect', 'deny')

        for policy_data in data.get('policies', []):
            try:
                effect_str = policy_data.get('effect', default_effect)
                effect = 'ALLOW' if effect_str.lower() == 'allow' else 'DENY'

                subjects = policy_data.get('subjects', {})
                conditions = policy_data.get('conditions', {})

                policy_dict = {
                    'name': policy_data['name'],
                    'policy_type': policy_data.get('policy_type', 'resource'),
                    'effect': effect,
                    'description': policy_data.get('description', ''),
                    'resource': policy_data.get('resources', []),
                    'actions': policy_data.get('actions', []),
                    'groups': subjects.get('groups', []),
                    'subject': subjects.get('users', []),
                    'context': conditions.get('context', {}),
                    'environment': conditions.get('environment', {}),
                    'conditions': conditions.get('context', {}),
                    'priority': policy_data.get('priority', 0),
                    'enforcing': policy_data.get('enforcing', False),
                }
                policies.append(policy_dict)
            except Exception as exc:
                logger.error(
                    f"Failed to parse policy "
                    f"'{policy_data.get('name', 'unknown')}' "
                    f"in {path}: {exc}"
                )
                continue

        return policies
