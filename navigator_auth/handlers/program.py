from typing import Any
from navigator_auth.models import ProgramCategory, Program, ProgramAttribute
from .model import ModelHandler

class ProgramCatHandler(ModelHandler):
    model: Any = ProgramCategory
    name: str = 'Program Category'
    pk: str = 'program_cat_id'


class ProgramHandler(ModelHandler):
    model: Any = Program
    name: str = 'Program'
    pk: str = 'program_id'

class ProgramAttrHandler(ModelHandler):
    model: Any = ProgramAttribute
    name: str = 'Program Attributes'
    pk: str = 'program_id'
