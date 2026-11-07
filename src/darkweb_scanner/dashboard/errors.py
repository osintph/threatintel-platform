"""
Error answers for the API.

The text of an exception can hold file paths, SQL, host names and addresses,
so it never goes into a response. A failure is logged once, with its traceback
and a short error id, and the client gets a plain message and that id:

    {"error": "<plain message>", "error_id": "<8 hex>"}

The id is what a user quotes and what the log is searched for.
"""

import json
import logging
import secrets

from flask import jsonify, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

GENERIC_MESSAGE = "Something went wrong on the server. Quote the error id when you report it."


def new_error_id() -> str:
    return secrets.token_hex(4)


def log_error(what: str, exc: BaseException | None = None) -> str:
    """Log a failure with its traceback under a new error id. Returns the id.

    Without ``exc`` the exception being handled is logged, so call it inside
    the ``except`` block.
    """
    error_id = new_error_id()
    logger.error("%s [error_id=%s]", what, error_id, exc_info=exc if exc is not None else True)
    return error_id


def api_error(message: str = GENERIC_MESSAGE, status: int = 500, *, what: str = "",
              exc: BaseException | None = None, error_id: str | None = None, **extra):
    """Log the failure and build the JSON answer for it.

    ``message`` is what the user reads: say what failed, never why in the
    exception's words. ``extra`` adds fields an endpoint has always sent
    (``ok``, ``data``) so that its answer keeps its shape.

    ``error_id`` is for a failure that log_error() has logged already (in a
    background job): the answer carries that id and nothing is logged again.
    """
    if error_id is None:
        error_id = log_error(what or f"{request.method} {request.path} failed", exc)
    return jsonify({**extra, "error": message, "error_id": error_id}), status


def install_error_handlers(app) -> None:
    """Catch-all for the API: no unhandled exception reaches the client as a traceback page.

    Under /api/ an unhandled exception is answered as api_error() does, and an
    HTTP error (404, 405, 413 ...) keeps its status and gets a JSON body.
    Everything else (HTML pages, redirects) is left to Flask as before.
    """

    @app.errorhandler(Exception)
    def _unhandled(exc):
        is_api = request.path.startswith("/api/")
        if isinstance(exc, HTTPException):
            if not is_api or exc.code is None or exc.code < 400:
                return exc
            response = exc.get_response()
            response.data = json.dumps({"error": exc.name})
            response.content_type = "application/json"
            return response
        if not is_api:
            raise exc
        return api_error(exc=exc)
