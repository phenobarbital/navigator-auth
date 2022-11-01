from datamodel import BaseModel
from navigator_auth.models import Client
from .model import ModelHandler

class ClientHandler(ModelHandler):
    model: BaseModel = Client
    name: str = 'Clients'
    pk: str = 'client_id'
