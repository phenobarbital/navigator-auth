from navigator_auth.exceptions import ConfigError
from .db import DBStorage

class pgStorage(DBStorage):
    """pgStorage.


    Getting Policies from Postgres Database.
    """
    driver: str = 'pg'
    timeout: int = 10

    async def load_policies(self):
        policy_table = """
        SELECT policy_id, policy_type, name, resource, actions, method, effect, groups,
        context, environment, description, objects, objects_attr, priority, org_id,
        client_id
        FROM auth.policies;"""
        async with self.connection() as conn:
            result, error = await conn.query(policy_table)
            if error:
                raise ConfigError(
                    f"ABAC: Error loading policies: {error}"
                )
        return result
