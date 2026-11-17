"""
The one Jinja2 environment, shared by both routers and the error handlers.

Autoescaping is on for .html templates (Jinja2Templates' default), so any
value rendered into a page is HTML-escaped. The secret itself never passes
through here at all: it is decrypted and displayed by script in the browser.
"""
from fastapi import Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")


def error_page(request: Request, status_code: int, title: str, message: str):
    """A deliberately generic page. Details of what went wrong go to the
    server log, not to whoever triggered the error."""
    return templates.TemplateResponse(
        request, "error.html", {"title": title, "message": message}, status_code=status_code
    )


def gone_page(request: Request):
    return templates.TemplateResponse(request, "gone.html", status_code=404)
