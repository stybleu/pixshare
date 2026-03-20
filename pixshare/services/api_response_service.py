from flask import jsonify


def api_success(payload: dict | None = None, status_code: int = 200):
    body = {"success": True}
    if payload:
        body.update(payload)
    return jsonify(body), status_code


def api_error(error: str, message: str, status_code: int = 400, extra: dict | None = None):
    body = {
        "success": False,
        "error": error,
        "message": message,
    }
    if extra:
        body.update(extra)
    return jsonify(body), status_code
