from navigator_auth.conf import (
    AUTH_TOKEN_ISSUER,
    AUTH_TOKEN_SECRET
)

class IdentityProvider:
    """IdP.

    Identity Provider for Navigator.
    """
    async def authenticate_credentials(self, login: str = None, password: str = None):
        print(login, password)
        return True

    def check_password(self, current_password, password):
        return True

    def set_password(
        self,
        password: str,
        token_num: int = 6,
        iterations: int = 80000,
        salt: str = None,
    ):
        return True

    def generate_authorization_code(self, client_id, redirect_uri):
        return 'X8p1rs_L2EyNMLnc9JOl8g.F6PL9yF42wgaGkIO_ajwwN_HF8M.LFTyeUldrU9KHfgBP4vT0-pSkt-yQIhRP0VI57W06GMLlcYmhVQwsP7LSU-L60wf2iClb_j1kbFYVr5FO0gyGYoPBO2QTIJefGf-jpSQbqMFdddOJfxIbfV2yfrsM3wcFcyxTezWMrJx5XKVwSKtXFR-x5NaaS8bp7EV2-7VvCsZZaXNT40oAd_qX8ft_HskI_Xv8qqs8QnBoAqOqtH8QmmYC8kB78HXOfFK027ut6ng30V4V9kUglx9janfviEOhP3aLeQMRngyGhgXxbYmIILxs9Xw_3azDdEozWKVr6YSxn9PP7cBDdOM-xfB-y1vkzsnf5Vhfb6vrRABdj_JEg'

    def check_authorization_code(self, code, client_id, redirect_uri):
        return True

    def create_token(self, user, data):
        return 'token', 30

    def decode_token(self, token):
        return True
