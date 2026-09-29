"""Authorisation: IRIS object access + cortex.* roles.

Object access reuses IRIS rules: effective case access (full access to execute, read-only to
view), or alerts_write / alerts_read plus access to the alert's customer. Roles come from IRIS
group membership (core.policy). Both are always required.
"""
from dataclasses import dataclass
from typing import Any, Optional, Set

from flask_login import current_user

from app.datamgmt.manage.manage_access_control_db import user_has_client_access
from app.iris_engine.access_control.utils import (
    ac_current_user_has_permission, ac_fast_check_current_user_has_case_access,
)
from app.models import Cases
from app.models.alerts import Alert
from app.models.authorization import CaseAccessLevel, Group, Permissions, UserGroup

from iris_cortex_module.core.policy import PolicyError, UserContext, effective_roles, require
from iris_cortex_module.core.settings import CortexSettings
from iris_cortex_module.integration.errors import CortexModuleError

CONTEXT_TYPES = ("case", "alert")


@dataclass
class Context:
    context_type: str
    context_id: int
    obj: Any
    customer_id: Optional[int]
    customer_name: Optional[str]
    title: str


def _deny() -> CortexModuleError:
    # Same answer whether the object does not exist or is not accessible (no enumeration).
    return CortexModuleError("Objeto não encontrado ou acesso negado.", 403)


def current_user_context() -> UserContext:
    names = {
        (row.group_name or "").strip().lower()
        for row in Group.query.with_entities(Group.group_name)
        .join(UserGroup, UserGroup.group_id == Group.group_id)
        .filter(UserGroup.user_id == current_user.id).all()
    }
    return UserContext(user_id=current_user.id, login=current_user.user, groups=frozenset(names),
                       is_server_admin=ac_current_user_has_permission(Permissions.server_administrator))


def roles_for_current_user(settings: CortexSettings) -> Set[str]:
    return effective_roles(current_user_context(), settings)


def require_role(settings: CortexSettings, role: str) -> Set[str]:
    roles = roles_for_current_user(settings)
    try:
        require(roles, role)
    except PolicyError as e:
        raise CortexModuleError(e.message, 403)
    return roles


def resolve_context(context_type: str, context_id: int, write: bool) -> Context:
    if context_type not in CONTEXT_TYPES:
        raise CortexModuleError("Contexto inválido (use case ou alert).", 400)
    try:
        context_id = int(context_id)
    except (TypeError, ValueError):
        raise CortexModuleError("Identificador de contexto inválido.", 400)

    if context_type == "case":
        levels = [CaseAccessLevel.full_access] if write else [CaseAccessLevel.read_only, CaseAccessLevel.full_access]
        if not ac_fast_check_current_user_has_case_access(context_id, levels):
            raise _deny()
        case = Cases.query.filter(Cases.case_id == context_id).first()
        if case is None:
            raise _deny()
        return Context("case", case.case_id, case, case.client_id, case.client.name if case.client else None,
                       case.name or "")

    if not ac_current_user_has_permission(Permissions.alerts_write if write else Permissions.alerts_read):
        raise _deny()
    alert = Alert.query.filter(Alert.alert_id == context_id).first()
    if alert is None or not user_has_client_access(current_user.id, alert.alert_customer_id):
        raise _deny()
    return Context("alert", alert.alert_id, alert, alert.alert_customer_id,
                   alert.customer.name if alert.customer else None, alert.alert_title or "")
