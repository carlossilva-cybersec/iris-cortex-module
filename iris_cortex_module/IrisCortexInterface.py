"""IRIS module interface: configuration screen + "Cortex Actions" manual hooks.

The hooks put a "Cortex Actions" entry in the IOC, evidence, case and alert menus; the
front-end script intercepts it and opens the Cortex dialog instead of queuing a module task.
"""
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes

from iris_cortex_module import MANUAL_HOOK_UI_NAME, MODULE_HUMAN_NAME, MODULE_VERSION
from iris_cortex_module.core.settings import PARAMETERS

MANUAL_HOOKS = ("on_manual_trigger_ioc", "on_manual_trigger_evidence", "on_manual_trigger_case",
                "on_manual_trigger_alert")


class IrisCortexInterface(IrisModuleInterface):
    _module_name = MODULE_HUMAN_NAME
    _module_description = "Run Cortex analyzers and responders on IOCs, evidences, files, cases and alerts"
    _interface_version = "1.2.0"
    _module_version = MODULE_VERSION
    _pipeline_support = False
    _pipeline_info = {}
    _module_configuration = PARAMETERS
    _module_type = IrisModuleTypes.module_processor

    def register_hooks(self, module_id: int):
        for hook in MANUAL_HOOKS:
            status = self.register_to_hook(module_id, iris_hook_name=hook, manual_hook_name=MANUAL_HOOK_UI_NAME,
                                           run_asynchronously=False)
            if status.is_failure():
                self.log.error(f"Failed to register {hook}: {status.get_message()}")
            else:
                self.log.info(f"Registered {hook}")

    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
        # Running analyzers needs the analyst's choices, collected by the Cortex dialog
        # (or POST /cortex-module/analyzers/run).
        self.log.info(f"{hook_name} called outside the Cortex dialog; use the /cortex-module API")
        return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))
