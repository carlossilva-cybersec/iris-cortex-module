"""HTTP API (mounted under /cortex-module). Authentication, API keys and CSRF are handled by IRIS'
``ac_api_requires``; roles and object access by the service layer."""
from functools import wraps
from pathlib import Path

from flask import Blueprint, request

from app.util import ac_api_requires, response_error, response_success

from iris_cortex_module.integration import service
from iris_cortex_module.integration.errors import CortexModuleError

MAX_JSON_BYTES = 256 * 1024

cortex_blueprint = Blueprint(
    "iris_cortex_module", __name__, url_prefix="/cortex-module",
    static_folder=str(Path(__file__).resolve().parent.parent / "static"), static_url_path="/static",
)


def _api(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except CortexModuleError as e:
            return response_error(e.message, data=e.data, status=e.status_code)
    return wrap


def _small_json(f):
    """Refuse oversized bodies before IRIS' CSRF check parses them."""
    @wraps(f)
    def wrap(*args, **kwargs):
        if request.content_length is None or request.content_length > MAX_JSON_BYTES:
            return response_error("Requisição muito grande.", status=413)
        return f(*args, **kwargs)
    return wrap


def _json() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise CortexModuleError("Corpo JSON inválido.", 400)
    return data


@cortex_blueprint.route("/status", methods=["GET"])
@ac_api_requires()
@_api
def status():
    return response_success(data=service.status())


@cortex_blueprint.route("/observables/<string:kind>/<int:object_id>", methods=["GET"])
@ac_api_requires()
@_api
def observable(kind, object_id):
    return response_success(data=service.catalog(kind, object_id, request.args.get("context_type", ""),
                                                 request.args.get("context_id", type=int)))


@cortex_blueprint.route("/analyzers/run", methods=["POST"])
@_small_json
@ac_api_requires()
@_api
def run_analyzers():
    executions = service.run_analyzers(_json())
    failed = [e for e in executions if e["status"] == "error"]
    message = f"{len(executions) - len(failed)} analyzer(s) enviados ao Cortex"
    if failed:
        message += f", {len(failed)} com erro"
    return response_success(message, data=executions)


@cortex_blueprint.route("/responders/run", methods=["POST"])
@_small_json
@ac_api_requires()
@_api
def run_responder():
    execution = service.run_responder(_json())
    if execution["status"] == "error":
        return response_error(execution["error_message"] or "Falha ao executar o responder", data=execution,
                              status=502)
    return response_success("Responder enviado ao Cortex", data=execution)


@cortex_blueprint.route("/executions/<int:execution_id>", methods=["GET"])
@ac_api_requires()
@_api
def execution(execution_id):
    return response_success(data=service.get_execution(execution_id))


@cortex_blueprint.route("/executions/<int:execution_id>/report", methods=["GET"])
@ac_api_requires()
@_api
def execution_report(execution_id):
    return response_success(data=service.get_execution(execution_id, include_report=True))


@cortex_blueprint.route("/executions/<int:execution_id>/import", methods=["POST"])
@_small_json
@ac_api_requires()
@_api
def import_artifacts(execution_id):
    result = service.import_artifacts(execution_id, _json().get("indexes"))
    ok = sum(1 for r in result["results"] if r["ok"])
    return response_success(f"{ok} item(ns) adicionados", data=result)


@cortex_blueprint.route("/executions/<int:execution_id>/operations/<int:index>/apply", methods=["POST"])
@_small_json
@ac_api_requires()
@_api
def apply_operation(execution_id, index):
    return response_success("Operação aplicada", data=service.apply_operation(execution_id, index))


@cortex_blueprint.route("/history/<string:context_type>/<int:context_id>", methods=["GET"])
@ac_api_requires()
@_api
def history(context_type, context_id):
    return response_success(data=service.history(context_type, context_id))


@cortex_blueprint.route("/logs", methods=["GET"])
@ac_api_requires()
@_api
def logs():
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 50, type=int), 1), 200)
    filters = {k: request.args.get(k) for k in ("status", "worker_type", "context_type", "object_kind", "user_login",
                                                  "worker")}
    filters["context_id"] = request.args.get("context_id", type=int)
    return response_success(data=service.logs(page, per_page, filters))
