from .clients import ClientHandler
from .orgs import OrganizationHandler
from .permissions import PermissionHandler
from .users import UserHandler, UserSession
from .program import ProgramCatHandler, ProgramHandler, ProgramClientHandler
from .groups import GroupHandler, GroupPermissionHandler, UserGroupHandler

## TODO migration of login/logout handlers:

def handler_routes(router) -> None:
    ## Clients
    router.add_view(
        r'/api/v1/clients/{id:.*}',
        ClientHandler,
        name='api_clients_id'
    )
    router.add_view(
        r'/api/v1/clients{meta:\:?.*}',
        ClientHandler,
        name='api_clients'
    )
    ## Organizations:
    router.add_view(
        r'/api/v1/organizations/{id:.*}',
        OrganizationHandler,
        name='api_organizations_id'
    )
    router.add_view(
        r'/api/v1/organizations{meta:\:?.*}',
        OrganizationHandler,
        name='api_organizations'
    )
    ### Programs:
    router.add_view(
        r'/api/v1/programs/{id:.*}',
        ProgramHandler,
        name='api_programs_id'
    )
    router.add_view(
        r'/api/v1/programs{meta:\:?.*}',
        ProgramHandler,
        name='api_programs'
    )
    router.add_view(
        r'/api/v1/program_categories/{id:.*}',
        ProgramCatHandler,
        name='api_program_categories_id'
    )
    router.add_view(
        r'/api/v1/program_categories{meta:\:?.*}',
        ProgramCatHandler,
        name='api_program_categories'
    )
    # Program Client:
    router.add_view(
        r'/api/v1/program_clients/{id:.*}',
        ProgramClientHandler,
        name='api_programs_clients_id'
    )
    router.add_view(
        r'/api/v1/program_clients{meta:\:?.*}',
        ProgramClientHandler,
        name='api_programs_clients'
    )
    ### Model permissions:
    router.add_view(
        r'/api/v1/permissions/{id:.*}',
        PermissionHandler,
        name='api_permissions_id'
    )
    router.add_view(
        r'/api/v1/permissions{meta:\:?.*}',
        PermissionHandler,
        name='api_permissions'
    )
    ### Groups:
    router.add_view(
        r'/api/v1/groups/{id:.*}',
        GroupHandler,
        name='api_groups_id'
    )
    router.add_view(
        r'/api/v1/groups{meta:\:?.*}',
        GroupHandler,
        name='api_groups'
    )
    router.add_view(
        r'/api/v1/user_groups/{id:.*}',
        UserGroupHandler,
        name='api_user_groups_id'
    )
    router.add_view(
        r'/api/v1/user_groups{meta:\:?.*}',
        UserGroupHandler,
        name='api_user_groups'
    )
    router.add_view(
        r'/api/v1/group_permissions/{id:.*}',
        GroupPermissionHandler,
        name='api_group_permissions_id'
    )
    router.add_view(
        r'/api/v1/group_permissions{meta:\:?.*}',
        GroupPermissionHandler,
        name='api_group_permissions'
    )
    ### User Methods:
    router.add_view(
        r'/api/v1/users/{id:.*}',
        UserHandler,
        name='api_auth_users_id'
    )
    router.add_view(
        r'/api/v1/users{meta:\:?.*}',
        UserHandler,
        name='api_auth_users'
    )
    ### User Session Methods:
    usr = UserSession()
    router.add_get("/api/v2/user/logout", usr.logout, allow_head=True)
    router.add_delete("/api/v2/user/logout", usr.logout)
    router.add_get("/api/v2/user/session", usr.user_session, allow_head=True)
    router.add_get("/api/v2/user/profile", usr.user_profile, allow_head=True)
    router.add_put("/api/v2/user/in_session", usr.in_session)
    router.add_post("/api/v2/user/set_password", usr.password_change)
    router.add_post("/api/v2/user/password_reset/{userid:.*}", usr.password_reset)
    router.add_get("/api/v2/user/gen_token/{userid:.*}", usr.gen_token, allow_head=True)
