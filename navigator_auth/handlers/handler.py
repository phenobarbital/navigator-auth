from navigator.views import ModelView


class ModelHandler(ModelView):
    """Extension for Using Model View on App Model.
    """
    dbname: str = 'authdb'

    async def _set_created_by(self, value, column, **kwargs):
        return await self.get_userid(session=self._session)
