"""Web extension entry point (``iris.web_extensions``), called once at start-up by the app AND the worker."""
from iris_cortex_module import MODULE_VERSION


def init_app(app):
    # Model import registers the table before IRIS' post-init create_all(); the jobs import
    # registers the Celery tasks in the worker.
    from iris_cortex_module.integration import models  # noqa: F401
    from iris_cortex_module.integration import jobs
    from iris_cortex_module.integration.routes import cortex_blueprint

    jobs.register_beat_schedule()
    app.register_blueprint(cortex_blueprint)
    app.config.setdefault("IRIS_WEB_EXTENSION_SCRIPTS", []).append(
        f"/cortex-module/static/iris_cortex.js?v={MODULE_VERSION}")
    app.config.setdefault("IRIS_WEB_EXTENSION_STYLESHEETS", []).append(
        f"/cortex-module/static/iris_cortex.css?v={MODULE_VERSION}")
    app.logger.info(f"iris_cortex_module web extension {MODULE_VERSION} loaded")
