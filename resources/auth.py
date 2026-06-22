from datetime import datetime
from aiohttp import web
from datamodel.exceptions import ValidationError
from asyncdb.drivers.pg import pg
from asyncdb.models import Column, Model
from asyncdb.exceptions import NoDataFound
from navconfig.logging import logging
from navigator_auth.conf import default_dsn
from navigator_auth.models import UserAttributes
from navigator_auth.conf import (
    AUTH_DB_SCHEMA,
    AUTH_USERS_VIEW
)


async def last_login(request: web.Request, user: Model, usermodel: Model, **kwargs):
    print("::: Calling last Login ::: ")
    logging.debug(
        f"User was logged in: {user.username}"
    )
    # making a connection, then, saving the last login to user.
    args = {
        "username": user["username"]
    }
    try:
        db = pg(dsn=default_dsn)
        async with await db.connection() as conn:
            usermodel.Meta.set_connection(conn)
            u = await usermodel.get(**args)
            u.last_login = datetime.utcnow()
            await u.update()
    except ValidationError as ex:
        print(ex)
        print(ex.payload)
    except Exception as ex:
        print(ex)
        logging.exception(ex, stack_info=True)


async def saving_troc_user(request: web.Request, user: Model, usermodel: Model, **kwargs):
    print(" ::: Calling TROC User ::: ")
    print("On this Function body we can get User data from other sources")
    print(" and merging that data into User Model, also, updating auth_user.")
    try:
        db = pg(dsn=default_dsn)
        userdata = kwargs['userdata']
        sql = """
        select associate_oid, associate_id, department_code, location_code,
        job_code, position_id from troc.troc_employees where corporate_email = '{email}'
        """
        sql = sql.format(email=user.username)
        args = {
            "user_id": user["user_id"]
        }
        async with await db.connection() as conn:
            userinfo = await conn.fetch_one(sql)
            userattr = {}
            if userinfo:
                ## also, set user attributes:
                UserAttributes.Meta.set_connection(conn)
                _new = False
                try:
                    attributes = await UserAttributes.get(**args)
                except NoDataFound:
                    attributes = UserAttributes(**args)
                    _new = True
                # insert new:
                if _new is True:
                    await attributes.insert()
                for key, val in userinfo.items():
                    userdata[key] = val
                    userattr[key] = val
                    setattr(attributes, key, val)
                try:
                    await attributes.update()
                except Exception as e:
                    print(e, type(e))
                usermodel.Meta.set_connection(conn)
                u = await usermodel.get(**args)
                u.attributes = userattr
                await u.update()
    except Exception as e:
        logging.exception(
            e, stack_info=True
        )
    finally:
        db = None

async def set_filtering_fixed(
    request: web.Request,
    user: Model,
    usermodel: Model,
    **kwargs
):
    """set_filtering_fixed.

        Calculate the Filtering Fixed.
    Args:
        request (web.Request): _description_
        user (Model): _description_
        usermodel (Model): _description_
        kwargs: other arguments
    """
    db = pg(dsn=default_dsn)
    ## Session Dictionary:
    userdata = kwargs['userdata']
    try:
        usr = {
            "user_id": user["user_id"]
        }
    except KeyError:
        return
    async with await db.connection() as conn:
        UserAttributes.Meta.set_connection(conn)
        try:
            usrattr = await UserAttributes.get(**usr)
            job_code = usrattr['job_code']
            location_code = usrattr['location_code']
        except NoDataFound:
            return
        gh = f"SELECT hierarchy, hlevel from walmart.group_hierarchy('{job_code}');"
        store_hierarchy = await conn.fetch_one(gh)
        try:
            hierarchy = store_hierarchy['hierarchy']
            hlevel = store_hierarchy['hlevel']
        except TypeError:
            # Job Position is not configured to use hierarchy
            return
        if hierarchy == 'store':
            sql = f"SELECT walmart.store_filtering('{location_code}', '{hlevel}')"
        elif hierarchy == 'market':
            sql = f"SELECT walmart.market_filtering('{location_code}')"
        elif hierarchy == 'district':
            sql = f"SELECT walmart.district_filtering('{location_code}')"
        elif hierarchy == 'region':
            sql = f"SELECT walmart.region_filtering('{location_code}')"
        elif hierarchy == 'territory':
            sql = f"SELECT walmart.territory_filtering('{location_code}')"
        try:
            print('SQL > ', sql)
            filter_fixed = await conn.fetch_one(sql)
            userdata['filtering_fixed'] = next(iter(filter_fixed.values()))
        except NoDataFound:
            return

class User(Model):
    """User using auth Schema."""

    user_id: int = Column(required=False, primary_key=True)
    first_name: str
    last_name: str
    display_name: str
    email: str = Column(required=False, max=254)
    alt_email: str = Column(required=False, max=254)
    password: str = Column(required=False, max=128)
    last_login: datetime = Column(required=False)
    username: str = Column(required=False)
    is_superuser: bool = Column(required=True, default=False)
    is_active: bool = Column(required=True, default=True)
    is_new: bool = Column(required=True, default=True)
    is_staff: bool = Column(required=False, default=True)
    title: str = Column(equired=False, max=90)
    avatar: str = Column(max=512)
    associate_id: str = Column(required=False)
    associate_oid: str = Column(required=False)
    # company: str = Column(required=False)
    department_code: str = Column(required=False)
    # department: str = Column(required=False)
    position_id: str = Column(required=False)
    group_id: list = Column(required=False)
    groups: list = Column(required=False)
    program_id: list = Column(required=False)
    programs: list = Column(required=False)
    created_at: datetime = Column(required=False)
    # date_joined: datetime = Column(required=False)

    class Meta:
        driver = "pg"
        name = AUTH_USERS_VIEW
        schema = AUTH_DB_SCHEMA
        strict = True
        frozen = False
        connection = None
