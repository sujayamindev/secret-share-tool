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


def humanize_minutes(minutes: int) -> str:
    """A lifetime in words for the create page, e.g. "24 hours". Whole hours
    up to two days read better as hours ("24 hours", not "1 day"); beyond
    that, whole days; anything else stays in minutes."""
    def plural(n: int, unit: str) -> str:
        return f"{n} {unit}" if n == 1 else f"{n} {unit}s"

    if minutes % 60 == 0 and minutes <= 48 * 60:
        return plural(minutes // 60, "hour")
    if minutes % (24 * 60) == 0:
        return plural(minutes // (24 * 60), "day")
    return plural(minutes, "minute")


def gone_page(request: Request):
    return templates.TemplateResponse(request, "gone.html", status_code=404)
