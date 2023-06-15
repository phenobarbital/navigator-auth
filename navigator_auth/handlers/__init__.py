from .permissions import PermissionHandler
from .users import UserHandler, UserSession
from .groups import GroupHandler, GroupPermissionHandler, UserGroupHandler
from .userattrs import UserAccountHandler, UserIdentityHandler
from .partners import PartnerKeyHandler

## TODO migration of login/logout handlers:
def handler_routes(router) -> None:
    ### Model permissions:
    router.add_view(
        r"/api/v1/permissions/{id:.*}", PermissionHandler,
        name="api_permissions_id"
    )
    router.add_view(
        r"/api/v1/permissions{meta:\:?.*}", PermissionHandler,
        name="api_permissions"
    )
    ## Groups:
    router.add_view(
        r"/api/v1/groups/{id:.*}", GroupHandler,
        name="api_groups_id"
    )
    router.add_view(
        r"/api/v1/groups{meta:\:?.*}", GroupHandler,
        name="api_groups"
    )
    router.add_view(
        r"/api/v1/user_groups/{id:.*}", UserGroupHandler,
        name="api_user_groups_id"
    )
    router.add_view(
        r"/api/v1/user_groups{meta:\:?.*}", UserGroupHandler,
        name="api_user_groups"
    )
    router.add_view(
        r"/api/v1/group_permissions/{id:.*}",
        GroupPermissionHandler,
        name="api_group_permissions_id",
    )
    router.add_view(
        r"/api/v1/group_permissions{meta:\:?.*}",
        GroupPermissionHandler,
        name="api_group_permissions",
    )
    ### User Methods:
    router.add_view(
        r"/api/v1/users/{id:.*}", UserHandler,
        name="api_auth_users_id"
    )
    router.add_view(
        r"/api/v1/users{meta:\:?.*}", UserHandler,
        name="api_auth_users"
    )
    # User Group:
    router.add_view(
        r"/api/v1/usergroups/{id:.*}", UserGroupHandler,
        name="api_auth_usergroups_id"
    )
    router.add_view(
        r"/api/v1/usergroups{meta:\:?.*}", UserGroupHandler,
        name="api_auth_usergroups"
    )
    # User Account:
    router.add_view(
        r"/api/v1/user_accounts/{id:.*}", UserAccountHandler,
        name="api_auth_useraccount_id"
    )
    router.add_view(
        r"/api/v1/user_accounts{meta:\:?.*}", UserAccountHandler,
        name="api_auth_useraccount"
    )
    # Partner Key Authentication Management
    router.add_view(
        r"/api/v1/partner/tokens/{id:.*}", PartnerKeyHandler,
        name="api_auth_partnerkey_id"
    )
    router.add_view(
        r"/api/v1/partner/tokens{meta:\:?.*}", PartnerKeyHandler,
        name="api_auth_partnerkey"
    )
    # User Account:
    router.add_view(
        r"/api/v1/user_identity/{id:.*}", UserIdentityHandler,
        name="api_auth_useridentity_id"
    )
    router.add_view(
        r"/api/v1/user_identity{meta:\:?.*}", UserIdentityHandler,
        name="api_auth_useridentity"
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
