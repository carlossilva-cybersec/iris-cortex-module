"""Authorisation decisions that do not need IRIS: cortex.* roles and classification policy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Set

from iris_cortex_module.core.datatypes import CORTEX_TLP_NAMES
from iris_cortex_module.core.settings import CortexSettings

ROLE_VIEW = "cortex.view"
ROLE_ANALYZER = "cortex.analyzer.execute"
ROLE_RESPONDER = "cortex.responder.execute"
ROLE_RESPONDER_PRIVILEGED = "cortex.responder.privileged"
ROLE_ADMIN = "cortex.admin"
ALL_ROLES = (ROLE_VIEW, ROLE_ANALYZER, ROLE_RESPONDER, ROLE_RESPONDER_PRIVILEGED, ROLE_ADMIN)


class PolicyError(PermissionError):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class UserContext:
    user_id: int
    login: str
    groups: frozenset          # lower-case IRIS group names
    is_server_admin: bool


def effective_roles(user: UserContext, settings: CortexSettings) -> Set[str]:
    """Roles granted by module configuration. Object-level access is checked separately.

    Empty group lists mean "everyone" for view/analyzer and "nobody but admins" for responders.
    """
    groups = set(user.groups)
    if user.is_server_admin or groups.intersection(settings.groups_admin):
        return set(ALL_ROLES)
    roles: Set[str] = set()
    if not settings.groups_view or groups.intersection(settings.groups_view):
        roles.add(ROLE_VIEW)
    if not settings.groups_analyzer or groups.intersection(settings.groups_analyzer):
        roles.update({ROLE_VIEW, ROLE_ANALYZER})
    if settings.groups_responder and groups.intersection(settings.groups_responder):
        roles.update({ROLE_VIEW, ROLE_RESPONDER})
    if settings.groups_responder_privileged and groups.intersection(settings.groups_responder_privileged):
        roles.update({ROLE_VIEW, ROLE_RESPONDER, ROLE_RESPONDER_PRIVILEGED})
    return roles


def require(roles: Iterable[str], role: str) -> None:
    if role not in set(roles):
        raise PolicyError({
            ROLE_VIEW: "Você não tem acesso aos recursos do Cortex.",
            ROLE_ANALYZER: "Você não tem permissão para executar analyzers.",
            ROLE_RESPONDER: "Você não tem permissão para executar responders.",
            ROLE_RESPONDER_PRIVILEGED: "Este responder executa ações de contenção e exige permissão específica.",
            ROLE_ADMIN: "Acesso restrito a administradores do módulo Cortex.",
        }.get(role, "Permissão negada."))


def responder_role(settings: CortexSettings, responder_name: str) -> str:
    return ROLE_RESPONDER_PRIVILEGED if settings.is_privileged_responder(responder_name) else ROLE_RESPONDER


def check_classification(settings: CortexSettings, tlp: int, pap: int) -> None:
    if tlp > settings.max_tlp:
        raise PolicyError(f"Observável TLP:{CORTEX_TLP_NAMES.get(tlp, tlp)} não pode ser enviado ao Cortex "
                          f"(máximo permitido: TLP:{CORTEX_TLP_NAMES.get(settings.max_tlp)}).")
    if pap > settings.max_pap:
        raise PolicyError(f"PAP {pap} acima do máximo permitido ({settings.max_pap}).")
