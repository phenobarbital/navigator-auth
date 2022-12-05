from typing import Any
from navigator_auth.models import (
    ProgramCategory,
    Program,
    ProgramAttribute,
    ProgramClient
)
from navigator_auth.conf import AUTH_PROGRAM_MODEL
from .model import ModelHandler


class ProgramHandler(ModelHandler):
    model: Any = Program
    model_name: str = AUTH_PROGRAM_MODEL
    name: str = 'Program'
    pk: str = 'program_id'

class ProgramCatHandler(ModelHandler):
    model: Any = ProgramCategory
    name: str = 'Program Category'
    pk: str = 'program_cat_id'

class ProgramAttrHandler(ModelHandler):
    model: Any = ProgramAttribute
    name: str = 'Program Attributes'
    pk: str = 'program_id'

class ProgramClientHandler(ModelHandler):
    model: Any = ProgramClient
    name: str = 'Program Client'
    pk: list = ['program_id', 'client_id']
