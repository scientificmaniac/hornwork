"""Web 业务 handler 域：按职责拆分的 mixin 集合。

server.py 的 _Handler 通过多继承装配这些 mixin；方法体通过 self 访问
传输层（_send_json/_send_bytes/_read_json/app/ctx 等）。
"""

from .authorize import AuthorizeMixin
from .auth import AuthMixin
from .integration import IntegrationMixin
from .events import EventsMixin
from .harden import HardenMixin
from .report import ReportMixin
from .lab import LabMixin
from .scan import ScanMixin
from .overview import OverviewMixin
from .rules import RulesMixin
from .intel import IntelMixin
from .cases import CasesMixin
from .validate import ValidateMixin
from .export import ExportMixin
from .metrics import MetricsMixin

__all__ = ["AuthorizeMixin", "AuthMixin", "IntegrationMixin", "EventsMixin", "HardenMixin", "ReportMixin", "LabMixin", "ScanMixin", "OverviewMixin", "RulesMixin", "IntelMixin", "CasesMixin", "ValidateMixin", "ExportMixin", "MetricsMixin"]
