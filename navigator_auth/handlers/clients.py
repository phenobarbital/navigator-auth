from datamodel import BaseModel
from navigator_auth.models import Client
from navigator_auth.conf import AUTH_CLIENT_MODEL
from .model import ModelHandler


class ClientHandler(ModelHandler):
    model: BaseModel = Client
    model_name: str = AUTH_CLIENT_MODEL
    name: str = "Clients"
    pk: str = "client_id"
