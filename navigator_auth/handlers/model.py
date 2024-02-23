"""
Model Handler: Abstract Model for managing Model with Views.
"""
from typing import Union, Optional, Any
import importlib
from aiohttp import web
from datamodel import BaseModel
from datamodel.exceptions import ValidationError
from asyncdb.exceptions import (
    DriverError,
    ProviderError,
    NoDataFound,
    StatementError,
    ModelError
)
from navigator_session import get_session
from navigator.views import BaseView
from ..exceptions import AuthException


class ModelHandler(BaseView):
    model: BaseModel = None
    model_name: str = None
    name: str = "Model"
    pk: Union[str, list] = "id"

    def __init__(self, request, *args, **kwargs):
        if self.model_name is not None:
            ## get Model from Variable
            self.model = self.get_authmodel(self.model_name)

        if hasattr(self.model.Meta, "pk") is True:
            self.pk = self.model.Meta.pk
        super(ModelHandler, self).__init__(request, *args, **kwargs)

    def get_authmodel(self, model: str):
        try:
            parts = model.split(".")
            name = parts[-1]
            classpath = ".".join(parts[:-1])
            module = importlib.import_module(classpath, package=name)
            obj = getattr(module, name)
            return obj
        except ImportError:
            ## Using fallback Model
            return self.model

    async def get_userid(self, session, idx: str = 'user_id') -> int:
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        try:
            if 'session' in session:
                return session['session'][idx]
            else:
                return session[idx]
        except KeyError:
            self.error(reason="Unauthorized", status=403)

    async def _get_data(self, session: Optional[Any] = None) -> Any:
        """_get_data.

        Get and pre-processing POST data before use it.
        """
        data = {}
        try:
            data = await self.json_data()
            for name, column in self.model.get_columns().items():
                ### if a function with name _get_{column name} exists
                ### then that function is called for getting the field value
                if hasattr(self, f'_get_{name}'):
                    fn = getattr(self, f'_get_{name}')
                    data[name] = await fn(
                        value=data.get(name, None),
                        column=column,
                        data=data
                    )
        except (TypeError, ValueError, AttributeError):
            self.error(
                reason=f"Invalid {self.name} Data", status=400
            )
        return data

    async def _post_get(self, result: Any, fields: list[str] = None) -> web.Response:
        """_post_get.

        Extensible for post-processing the GET response.
        """
        if not result:
            return self.no_content()
        else:
            if fields is not None:
                if isinstance(result, list):
                    new = []
                    for r in result:
                        row = {}
                        for field in fields:
                            row[field] = getattr(r, field, None)
                        new.append(row)
                    result = new
                else:
                    ## filtering result to returning only fields asked:
                    result = {}
                    for field in fields:
                        result[field] = getattr(result, field, None)
            return self.json_response(content=result)

    async def session(self):
        self._session = None
        try:
            self._session = await get_session(self.request)
        except (ValueError, RuntimeError) as err:
            return self.critical(
                reason="Error Decoding Session", request=self.request, exception=err
            )
        if not self._session:
            self.error(
                reason={"message": "Unauthorized"},
                status=403
            )
        return self._session

    async def head(self):
        """Getting Client information."""
        session = await self.session()
        ## calculating resource:
        response = self.model.schema(as_dict=True)
        columns = list(response["properties"].keys())
        size = len(str(response))
        headers = {
            "Content-Length": size,
            "X-Columns": f"{columns!r}",
            "X-Model": self.model.__name__,
            "X-Tablename": self.model.Meta.name,
            "X-Schema": self.model.Meta.schema,
        }
        return self.no_content(headers=headers)

    async def get(self):
        """Getting Client information."""
        session = await self.session()
        ## getting all clients:
        params = self.match_parameters(self.request)
        try:
            if params["meta"] == ":meta":
                # returning JSON schema of Model:
                response = self.model.schema(as_dict=True)
                return self.json_response(content=response)
        except KeyError:
            pass
        ## validate directly with model:
        db = self.request.app["authdb"]
        ## getting first the id from params or data:
        args = {}
        qp = self.query_parameters(request=self.request)
        try:
            fields = qp['fields'].split(',')
            del qp['fields']
        except KeyError:
            fields = None
        if isinstance(self.pk, str):
            try:
                objid = params[self.pk]
            except (TypeError, KeyError):
                try:
                    objid = params["id"]
                except KeyError:
                    objid = None
            if objid:
                args = {self.pk: objid}
        elif isinstance(self.pk, list):
            try:
                paramlist = params["id"].split("/")
                if len(paramlist) != len(self.pk):
                    return self.error(
                        reason=f"Invalid Number of URL elements for PK: {self.pk}, {paramlist!r}",
                        status=410,
                    )
                args = {}
                for key in self.pk:
                    args[key] = paramlist.pop(0)
            except KeyError:
                pass
        else:
            return self.error(
                reason=f"Invalid PK definition for {self.name}: {self.pk}", status=410
            )
        if args:
            # get data for specific client:
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                # look for this client, after, save changes
                error = {"error": f"{self.name} was not Found"}
                try:
                    result = await self.model.get(**args)
                except ModelError as ex:
                    error = {
                        "error": f"Missing Info for Model {self.name}",
                        "payload": str(ex)
                    }
                    return self.error(reason=error, status=400)
                except NoDataFound:
                    self.error(reason=error, status=404)
                if not result:
                    self.error(reason=error, status=404)
                return await self._post_get(result, fields=fields)
        else:
            try:
                async with await db.acquire() as conn:
                    self.model.Meta.connection = conn
                    if qp:
                        result = await self.model.filter(**qp)
                    else:
                        result = await self.model.all()
                    return await self._post_get(result, fields=fields)
            except ModelError as ex:
                error = {
                    "error": f"Missing Info for Model {self.name}",
                    "payload": str(ex)
                }
                return self.error(reason=error, status=400)
            except ValidationError as ex:
                error = {
                    "error": f"Unable to load {self.name} info from Database",
                    "payload": ex.payload,
                }
                return self.critical(reason=error, status=501)
            except TypeError as ex:
                error = {
                    "error": f"Invalid payload for {self.name}",
                    "payload": str(ex),
                }
                return self.error(reason=error, status=406)
            except (DriverError, ProviderError, RuntimeError) as ex:
                error = {
                    "error": "Database Error",
                    "payload": str(ex),
                }
                return self.critical(reason=error, status=500)

    async def put(self):
        """Creating Model information."""
        session = await self.session()
        ### get session Data:
        data = await self._get_data(session=session)
        ## validate directly with model:
        try:
            resultset = self.model(**data)  # pylint: disable=E1102
            db = self.request.app["authdb"]
            async with await db.acquire() as conn:
                resultset.Meta.connection = conn
                result = await resultset.insert()
                return self.json_response(content=result, status=201)
        except ModelError as ex:
            error = {
                "error": f"Missing Info for Model {self.name}",
                "payload": str(ex)
            }
            return self.error(reason=error, status=400)
        except ValidationError as ex:
            error = {
                "error": f"Unable to insert {self.name} info",
                "payload": ex.payload,
            }
            return self.error(reason=error, status=406)
        except StatementError as ex:
            # UniqueViolation, already exists:
            error = {
                "error": f"Record already exists for {self.name}",
                "payload": str(ex),
            }
            return self.error(reason=error, status=412)
        except (TypeError, AttributeError, ValueError) as ex:
            error = {
                "error": f"Invalid payload for {self.name}",
                "payload": str(ex),
            }
            return self.error(reason=error, status=406)

    async def patch(self):
        """Patch an existing Client or retrieve the column names."""
        session = await self.session()
        ### get session Data:
        params = self.match_parameters()
        try:
            if params["meta"] == ":meta":
                ## returning the columns on Model:
                fields = self.model.__fields__
                return self.json_response(content=fields)
        except KeyError:
            pass
        ### get session Data:
        data = await self._get_data(session=session)
        ## validate directly with model:
        ## getting first the id from params or data:
        args = {}
        if isinstance(self.pk, str):
            try:
                objid = data[self.pk]
            except (TypeError, KeyError):
                objid = params["id"]
            args = {self.pk: objid}
        elif isinstance(self.pk, list):
            try:
                paramlist = params["id"].split("/")
                if len(paramlist) != len(self.pk):
                    return self.error(
                        reason=f"Invalid Number of URL elements for PK: {self.pk}, {paramlist!r}",
                        status=410,
                    )
                args = {}
                for key in self.pk:
                    args[key] = paramlist.pop(0)
            except KeyError:
                pass
        else:
            return self.error(
                reason=f"Invalid PK definition for {self.name}: {self.pk}", status=410
            )
        db = self.request.app["authdb"]
        if args:
            ## getting client
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                try:
                    result = await self.model.get(**args)
                except ModelError as ex:
                    error = {
                        "error": f"Missing Info for Model {self.name}",
                        "payload": str(ex)
                    }
                    return self.error(reason=error, status=400)
                except NoDataFound:
                    headers = {"x-error": f"{self.name} was not Found"}
                    self.no_content(headers=headers)
                if not result:
                    headers = {"x-error": f"{self.name} was not Found"}
                    self.no_content(headers=headers)
                ## saved with new changes:
                for key, val in data.items():
                    if key in result.get_fields():
                        result.set(key, val)
                data = await result.update()
                return self.json_response(content=data, status=202)
        else:
            self.error(reason=f"Invalid {self.name} Data to Patch", status=400)

    async def post(self):
        """Create or Update a Client."""
        session = await self.session()
        ### get session Data:
        params = self.match_parameters()
        data = await self._get_data(session=session)
        ## validate directly with model:
        ## getting first the id from params or data:
        args = {}
        if isinstance(self.pk, str):
            try:
                objid = data[self.pk]
            except (TypeError, KeyError):
                objid = params["id"]
            args = {self.pk: objid}
        elif isinstance(self.pk, list):
            try:
                paramlist = params["id"].split("/")
                if len(paramlist) != len(self.pk):
                    return self.error(
                        reason=f"Invalid Number of URL elements for PK: {self.pk}, {paramlist!r}",
                        status=410,
                    )
                args = {}
                for key in self.pk:
                    args[key] = paramlist.pop(0)
            except KeyError:
                pass
        else:
            return self.error(
                reason=f"Invalid PK definition for {self.name}: {self.pk}", status=410
            )
        db = self.request.app["authdb"]
        if args:
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                # look for this client, after, save changes
                error = {"error": f"{self.name} was not Found"}
                try:
                    result = await self.model.get(**args)
                except (NoDataFound, ModelError):
                    # create new Record
                    result = None
                if not result:
                    try:
                        resultset = self.model(**data)  # pylint: disable=E1102
                        result = await resultset.insert()
                        return self.json_response(content=result, status=201)
                    except ModelError as ex:
                        error = {
                            "error": f"Missing Info for Model {self.name}",
                            "payload": str(ex)
                        }
                        return self.error(reason=error, status=400)
                    except ValidationError as ex:
                        error = {
                            "error": f"Unable to insert {self.name} info",
                            "payload": ex.payload,
                        }
                        return self.error(reason=error, status=406)
                ## saved with new changes:
                for key, val in data.items():
                    if key in result.get_fields():
                        result.set(key, val)
                data = await result.update()
                return self.json_response(content=data, status=202)
        else:
            # create a new client based on data:
            try:
                resultset = self.model(**data)  # pylint: disable=E1102
                async with await db.acquire() as conn:
                    resultset.Meta.connection = conn
                    result = await resultset.insert()  # TODO: migrate to use save()
                    return self.json_response(content=result, status=201)
            except ModelError as ex:
                error = {
                    "error": f"Missing Info for Model {self.name}",
                    "payload": str(ex)
                }
                return self.error(reason=error, status=400)
            except ValidationError as ex:
                error = {
                    "error": f"Unable to insert {self.name} info",
                    "payload": ex.payload,
                }
                return self.error(reason=error, status=406)
            except (TypeError, AttributeError, ValueError) as ex:
                error = {
                    "error": f"Invalid payload for {self.name}",
                    "payload": str(ex),
                }
                return self.error(exception=error, status=406)

    async def delete(self):
        """Delete a Client."""
        session = await self.session()
        ### get session Data:
        params = self.match_parameters()
        try:
            data = await self._get_data(session=session)
        except AuthException:
            data = None
        except (TypeError, ValueError):
            self.error(
                reason=f"Invalid {self.name} Data", status=406
            )
        ## getting first the id from params or data:
        args = {}
        if isinstance(self.pk, str):
            try:
                objid = data[self.pk]
            except (TypeError, KeyError):
                objid = params["id"]
            args = {self.pk: objid}
        elif isinstance(self.pk, list):
            try:
                paramlist = params["id"].split("/")
                if len(paramlist) != len(self.pk):
                    return self.error(
                        reason=f"Invalid Number of URL elements for PK: {self.pk}, {paramlist!r}",
                        status=410,
                    )
                args = {}
                for key in self.pk:
                    args[key] = paramlist.pop(0)
            except KeyError:
                pass
        else:
            return self.error(
                reason=f"Invalid PK definition for {self.name}: {self.pk}", status=410
            )
        db = self.request.app["authdb"]
        if args:
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                # look for this client, after, save changes
                result = await self.model.get(**args)
                if not result:
                    self.error(reason=f"{self.name} was Not Found", status=204)
                # Delete them this Client
                data = await result.delete()
                return self.json_response(content=data, status=202)
        else:
            self.error(reason=f"Cannot Delete an Empty {self.name}", status=204)
