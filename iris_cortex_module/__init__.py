"""DFIR-IRIS <-> Cortex integration.

* ``IrisCortexInterface`` -- classic IRIS module: configuration screen and the "Cortex Actions"
  manual hooks on IOCs, evidences, cases and alerts.
* ``integration.extension:init_app`` -- web extension (blueprint, models, Celery tasks, UI script),
  loaded through the ``iris.web_extensions`` entry point.

``iris_cortex_module.core`` never imports IRIS or Flask.
"""

__iris_module_interface = "IrisCortexInterface"

MODULE_PACKAGE_NAME = "iris_cortex_module"
MODULE_HUMAN_NAME = "IrisCortex"
MODULE_VERSION = "1.0.0"
MANUAL_HOOK_UI_NAME = "Cortex Actions"
