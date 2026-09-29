"""Read the module configuration saved by IRIS (Advanced > Modules)."""
from app.models import IrisModule

from iris_cortex_module import MODULE_PACKAGE_NAME
from iris_cortex_module.core.settings import ConfigError, CortexSettings
from iris_cortex_module.integration.errors import CortexModuleError


def _params_to_dict(module_config) -> dict:
    values = {}
    for param in module_config or []:
        name = param.get("param_name")
        if name:
            values[name] = param.get("value") if param.get("value") is not None else param.get("default")
    return values


def load_settings() -> CortexSettings:
    """Effective settings, re-read on every call (changes apply without restart)."""
    module = IrisModule.query.with_entities(IrisModule.is_active, IrisModule.module_config).filter(
        IrisModule.module_name == MODULE_PACKAGE_NAME).first()
    if module is None:
        raise CortexModuleError("Módulo Cortex não registrado. Um administrador deve adicionar "
                                f"'{MODULE_PACKAGE_NAME}' em Advanced > Modules.", 503)
    if not module.is_active:
        raise CortexModuleError("Módulo Cortex desativado.", 503)
    try:
        return CortexSettings.from_sources(_params_to_dict(module.module_config))
    except ConfigError as e:
        raise CortexModuleError(f"Módulo Cortex mal configurado: {e}", 503)
