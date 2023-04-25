from collections.abc import Iterable
from .abstract import UserAttribute


class DomainAttribute(UserAttribute):
    name: str = "domain"

    def get_value(self, user: Iterable, userdata: dict, **kwargs):
        mail = user['email']
        if mail:
            mailparts = mail.split('@')
            userdata['user'] = mailparts[0]
            return mailparts[1]
