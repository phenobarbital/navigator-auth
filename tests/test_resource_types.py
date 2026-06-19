"""Unit tests for new ResourceType / ActionType values (FEAT-091 QuerySource pbac-support)."""
from navigator_auth.abac.policies.resources import ResourceType, ActionType


class TestNewResourceTypes:
    def test_slug(self):
        assert ResourceType.SLUG.value == "slug"

    def test_datasource(self):
        assert ResourceType.DATASOURCE.value == "datasource"

    def test_driver(self):
        assert ResourceType.DRIVER.value == "driver"

    def test_raw_query(self):
        assert ResourceType.RAW_QUERY.value == "raw_query"

    def test_existing_values_unchanged(self):
        """Ensure no existing values were renamed or removed."""
        assert ResourceType.TOOL.value == "tool"
        assert ResourceType.KB.value == "kb"
        assert ResourceType.AGENT.value == "agent"
        assert ResourceType.DATASET.value == "dataset"


class TestNewActionTypes:
    def test_slug_execute(self):
        assert ActionType.SLUG_EXECUTE.value == "slug:execute"

    def test_slug_list(self):
        assert ActionType.SLUG_LIST.value == "slug:list"

    def test_datasource_use(self):
        assert ActionType.DATASOURCE_USE.value == "datasource:use"

    def test_datasource_list(self):
        assert ActionType.DATASOURCE_LIST.value == "datasource:list"

    def test_driver_use(self):
        assert ActionType.DRIVER_USE.value == "driver:use"

    def test_driver_list(self):
        assert ActionType.DRIVER_LIST.value == "driver:list"

    def test_raw_query_execute(self):
        assert ActionType.RAW_QUERY_EXECUTE.value == "raw_query:execute"

    def test_all_new_actions_present(self):
        expected = {
            "slug:execute", "slug:list",
            "datasource:use", "datasource:list",
            "driver:use", "driver:list",
            "raw_query:execute",
        }
        actual = {a.value for a in ActionType}
        assert expected.issubset(actual), (
            f"Missing action types: {expected - actual}"
        )

    def test_existing_actions_unchanged(self):
        """Ensure existing action types are still present."""
        assert ActionType.TOOL_EXECUTE.value == "tool:execute"
        assert ActionType.AGENT_CHAT.value == "agent:chat"
