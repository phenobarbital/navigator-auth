from datamodel.exceptions import ValidationError
from asyncdb.exceptions import DriverError, ProviderError, NoDataFound
from navigator_session import get_session
from navigator_auth.models import Client
from navigator_auth.exceptions import AuthException
from .base import BaseView


class ClientHandler(BaseView):

    async def session(self):
        session = None
        try:
            session = await get_session(self.request)
        except (ValueError, RuntimeError) as err:
            return self.critical(
                reason="Error Decoding Session",
                request=self.request,
                exception=err
            )
        return session

    async def head(self):
        """ Getting Client information."""
        session = await self.session()
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        ## calculating resource:
        response = Client.schema(as_dict=True)
        columns = list(response["properties"].keys())
        size = len(str(response))
        headers = {
            "Content-Length": size,
            "X-Columns": f"{columns!r}",
            "X-Model": Client.__name__,
        }
        return self.no_content(
            headers=headers
        )

    async def get(self):
        """ Getting Client information."""
        session = await self.session()
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        ## getting all clients:
        args = self.match_parameters(self.request)
        try:
            if args['meta'] == ':meta':
                # returning JSON schema of Model:
                response = Client.schema(as_dict=True)
                return self.json_response(content=response)
        except KeyError:
            pass
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            data = None
        ## validate directly with model:
        db = self.request.app['authdb']
        ## getting first the id from params or data:
        try:
            clientid = data['client_id']
        except (TypeError, KeyError):
            clientid = args['id']
        if clientid:
            # get data for specific client:
            async with await db.acquire() as conn:
                Client.Meta.connection = conn
                # look for this client, after, save changes
                error = {
                    "error": "Client was not Found"
                }
                try:
                    client = await Client.get(client_id=clientid)
                except NoDataFound:
                    self.error(
                        exception=error,
                        status=403
                    )
                if not client:
                    self.error(
                        exception=error,
                        status=403
                    )
                return self.json_response(content=client)
        else:
            try:
                async with await db.acquire() as conn:
                    Client.Meta.connection = conn
                    result = await Client.all()
                    return self.json_response(content=result)
            except ValidationError as ex:
                error = {
                    "error": "Unable to load Client info from Database",
                    "payload": ex.payload,
                }
                return self.critical(
                    reason=error,
                    statu=501
                )
            except (DriverError, ProviderError, RuntimeError):
                error = {
                    "error": "Database Error",
                    "payload": ex,
                }
                return self.critical(
                    reason=error,
                    statu=500
                )

    async def put(self):
        """ Creating Client information."""
        session = await self.session()
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            self.error(
                reason="Invalid Client Data",
                status=403
            )
        ## validate directly with model:
        try:
            resultset = Client(**data)
            db = self.request.app['authdb']
            async with await db.acquire() as conn:
                resultset.Meta.connection = conn
                result = await resultset.insert()
                return self.json_response(content=result, status=201)
        except ValidationError as ex:
            error = {
                "error": "Unable to insert Client info",
                "payload": ex.payload,
            }
            return self.error(
                reason=error,
                statu=501
            )

    async def patch(self):
        """ Patch an existing Client or retrieve the column names."""
        session = await self.session()
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        params = self.match_parameters()
        try:
            if params['meta'] == ':meta':
                ## returning the columns on Model:
                fields = Client.__fields__
                return self.json_response(content=fields)
        except KeyError:
            pass
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            self.error(
                reason="Invalid Client Data",
                status=403
            )
        ## validate directly with model:
        ## getting first the id from params or data:
        try:
            clientid = data['client_id']
        except (TypeError, KeyError):
            clientid = params['id']
        db = self.request.app['authdb']
        if clientid:
            ## getting client
            async with await db.acquire() as conn:
                Client.Meta.connection = conn
                try:
                    client = await Client.get(client_id=clientid)
                except NoDataFound:
                    headers = {
                        "x-error": "Client was not Found"
                    }
                    self.no_content(
                        headers=headers
                    )
                if not client:
                    headers = {
                        "x-error": "Client was not Found"
                    }
                    self.no_content(
                        headers=headers
                    )
                ## saved with new changes:
                for key, val in data.items():
                    if key in client.get_fields():
                        client.set(key, val)
                result = await client.update()
                return self.json_response(content=result, status=202)
        else:
            self.error(
                reason="Invalid Client Data",
                status=403
            )

    async def post(self):
        """ Create or Update a Client."""
        session = await self.session()
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        params = self.match_parameters()
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            self.error(
                reason="Invalid Client Data",
                status=403
            )
        ## validate directly with model:
        ## getting first the id from params or data:
        try:
            clientid = data['client_id']
        except (TypeError, KeyError):
            clientid = params['id']
        db = self.request.app['authdb']
        if clientid:
            async with await db.acquire() as conn:
                Client.Meta.connection = conn
                # look for this client, after, save changes
                error = {
                    "error": "Client was not Found"
                }
                try:
                    client = await Client.get(client_id=clientid)
                except NoDataFound:
                    self.error(
                        exception=error,
                        status=403
                    )
                if not client:
                    self.error(
                        exception=error,
                        status=403
                    )
                ## saved with new changes:
                for key, val in data.items():
                    if key in client.get_fields():
                        client.set(key, val)
                result = await client.update()
                return self.json_response(content=result, status=202)
        else:
            # create a new client based on data:
            try:
                resultset = Client(**data)
                async with await db.acquire() as conn:
                    resultset.Meta.connection = conn
                    result = await resultset.insert() # TODO: migrate to use save()
                    return self.json_response(content=result, status=201)
            except ValidationError as ex:
                error = {
                    "error": "Unable to insert Client info",
                    "payload": ex.payload,
                }
                return self.error(
                    reason=error,
                    statu=501
                )

    async def delete(self):
        """ Delete a Client."""
        session = await self.session()
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        params = self.match_parameters()
        try:
            data = await self.json_data()
        except AuthException:
            data = None
        except (TypeError, ValueError):
            self.error(
                reason="Invalid Client Data",
                status=403
            )
        ## getting first the id from params or data:
        try:
            clientid = data['client_id']
        except (TypeError, KeyError):
            clientid = params['id']
        db = self.request.app['authdb']
        if clientid:
            async with await db.acquire() as conn:
                Client.Meta.connection = conn
                # look for this client, after, save changes
                client = await Client.get(client_id=clientid)
                if not client:
                    self.error(
                        reason="Client was Not Found",
                        status=204
                    )
                # Delete them this Client
                result = await client.delete()
                return self.json_response(content=result, status=202)
        else:
            self.error(
                reason="Cannot Delete an Empty Client ID",
                status=204
            )
