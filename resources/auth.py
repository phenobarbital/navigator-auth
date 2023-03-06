from datetime import datetime
from aiohttp import web
from asyncdb.drivers.pg import pg
from asyncdb.models import Model
from asyncdb.exceptions import NoDataFound, ProviderError, DriverError
from navconfig.logging import logging
from navigator_auth.conf import default_dsn
from navigator_auth.models import UserAttributes


async def last_login(request: web.Request, user: Model, usermodel: Model, **kwargs):
    print("::: Calling last Login ::: ")
    logging.debug(f"User was logged in: {user.username}")
    # making a connection, then, saving the last login to user.
    args = {
        "user_id": user["user_id"]
    }
    try:
        db = pg(dsn=default_dsn)
        async with await db.connection() as conn:
            usermodel.Meta.set_connection(conn)
            u = await usermodel.get(**args)
            u.last_login = datetime.utcnow()
            await u.update()
    except Exception as e:
        logging.exception(e, stack_info=True)
    finally:
        db = None


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
                for key, val in userinfo.items():
                    userdata[key] = val
                    userattr[key] = val
                    try:
                        setattr(attributes, key, val)
                        if _new is True:
                            await attributes.insert()
                        else:
                            await attributes.update()
                    except (ProviderError, DriverError) as ex:
                        logging.warning(str(ex))
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
