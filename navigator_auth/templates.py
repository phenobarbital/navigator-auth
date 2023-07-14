from typing import Optional
from collections.abc import Callable
from pathlib import Path
from aiohttp import web
from navconfig import config
from jinja2 import Environment, FileSystemLoader, TemplateError, TemplateNotFound

jinja_config = {
    "enable_async": True,
    "extensions": ["jinja2.ext.i18n", "jinja2.ext.loopcontrols"],
}


class TemplateParser:
    """
    TemplateParser.

    This is a wrapper for the Jinja2 template engine.
    """

    def __init__(
        self,
        directory: Path,
        filters: Optional[list] = None,
        **kwargs
    ):
        self.template = None
        self.path = directory.resolve()
        self.filters = filters
        if not self.path.exists():
            raise RuntimeError(
                f"Notify: template directory {directory} does not exist"
            )
        if "config" in kwargs:
            self.config = {**jinja_config, **kwargs["config"]}
        else:
            self.config = jinja_config
        template_debug = config.getboolean(
            "TEMPLATE_DEBUG", fallback=False
        )
        if template_debug is True:
            self.config["extensions"].append("jinja2.ext.debug")
        # creating loader:
        templateLoader = FileSystemLoader(
            searchpath=[str(self.path)]
        )
        # initialize the environment
        try:
            # TODO: check the bug ,encoding='ANSI'
            self.env: Optional[Environment] = Environment(
                loader=templateLoader, **self.config
            )
            # compiled_path = BytesIO()
            compiled_path = str(
                self.path.joinpath(".compiled")
            )
            self.env.compile_templates(
                target=compiled_path, zip="deflated"
            )
        except Exception as err:
            raise RuntimeError(
                f"Notify: Error loading Template Environment: {err}"
            ) from err
        ### adding custom filters:
        if self.filters is not None:
            self.env.filters.update(self.filters)

    def get_template(self, filename: str):
        """
        Get a template from Template Environment using the Filename.
        """
        try:
            self.template = self.env.get_template(str(filename))
            return self.template
        except TemplateNotFound as ex:
            raise FileNotFoundError(
                f"Template cannot be found: {filename}"
            ) from ex
        except Exception as ex:
            raise RuntimeError(
                f"Error parsing Template {filename}: {ex}"
            ) from ex

    @property
    def environment(self):
        return self.env

    def add_filter(self, func: Callable, name: Optional[str] = None) -> None:
        """add_filter.
        Register a custom function as Template Filter.
        """
        if name is not None:
            filter_name = name
        elif callable(func):
            filter_name = name.__name__
        else:
            raise TypeError(f"Template Filter must be a callable function: {func!r}")
        self.env.filters[filter_name] = func

    def render(self, filename: str, params: Optional[dict] = None) -> str:
        if not params:
            params = {}
        result = None
        try:
            self.template = self.env.get_template(str(filename))
            result = self.template.render(**params)
            return result
        except Exception as err:
            raise RuntimeError(
                f"Notify: Error rendering template: {filename}, error: {err}"
            ) from err

    async def render_async(self, filename: str, params: Optional[dict] = None) -> str:
        """Render.
        Renders a Jinja2 template using async-await syntax.
        """
        result = None
        if not params:
            params = {}
        try:
            template = self.env.get_template(str(filename))
            result = await template.render_async(**params)
            return result
        except TemplateError as ex:
            raise ValueError(
                f"Template parsing error, template: {filename}: {ex}"
            ) from ex
        except Exception as err:
            raise RuntimeError(
                f"NAV: Error rendering: {filename}, error: {err}"
            ) from err

    async def view(
        self,
        filename: str,
        params: Optional[dict] = None,
        content_type: str = 'text/html',
        charset: Optional[str] = "utf-8",
        status: int = 200,
    ) -> web.Response:
        """view.
        description: view Method can return a Web Response from a Template content.
        Args:
            filename (str): Template name in template directory.
            params (Optional[dict]): Params passed to Template. Defaults to None.
            content_type (str): Content Type of the Response. Defaults to 'text/html'.
            charset (Optional[str], optional): Charset of View. Defaults to "utf-8".
            status (int, optional): Optional HTTP method status. Defaults to 200 (OK).

        Raises:
            web.HTTPNotFound: When Template is missing or can't be parsed.
            web.HTTPBadRequest: When Template cannot be rendered.

        Returns:
            web.Response: an HTTP Web Response with Template result in the Body.
        """
        if not params:
            params = {}
        args = {
            "content_type": content_type,
            "headers": {
                'X-TEMPLATE': filename
            }
        }
        try:
            template = self.env.get_template(str(filename))
        except Exception as ex:
            # return 404 Not Found:
            args['headers']['X-TEMPLATE-ERROR'] = str(ex)
            raise web.HTTPNotFound(
                reason=f'Missing or Wrong Template file: {filename}: \n {ex!s}',
                **args
            )
        ## processing the template:
        try:
            result = await template.render_async(**params)
            response = {
                "content_type": content_type,
                "charset": charset,
                "status": status,
                "body": result
            }
            return web.Response(**response)
        except Exception as ex:
            args['headers']['X-TEMPLATE-ERROR'] = str(ex)
            raise web.HTTPBadRequest(
                reason=f'Error Parsing Template {filename}: {ex}',
                **args
            )
