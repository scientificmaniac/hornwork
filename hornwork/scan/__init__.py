"""扫描模块：定期漏洞扫描子系统（scan）。

设计依据：[模块3开发思路-v1-自研扫描框架与复用引擎.md]；实现决策（v2）：
- **端口发现与服务版本识别直接复用 nmap**（`-sV` + XML），不再自研 connect/banner，
  由 :mod:`hornwork.scan.engines.nmap_adapter` 以独立进程调用并解析；
- 编排（计划/槽位/闸门/续跑）、归一/去重/生命周期、CVE 区间匹配、快照差异、覆盖率、
  报告全部自研；
- 复用件（nmap/lynis/testssl.sh/nuclei）一律"独立进程 + 标准接口 + 可一键禁用 + 有降级路径"。

子模块：
- :mod:`hornwork.scan.store`     数据访问层与全部 DDL（复用 hornwork.db）；
- :mod:`hornwork.scan.assets`    台账高层操作（注册、声明端口、目标选择）；
- :mod:`hornwork.scan.scheduler` 周期槽位、时间窗、白名单、资源闸门；
- :mod:`hornwork.scan.task`      任务幂等创建 / 状态机 / 断点续跑；
- :mod:`hornwork.scan.engines`   引擎适配器（nmap 为主，pkgs/lynis/testssl/nuclei 可选）；
- :mod:`hornwork.scan.normalize` RawResult → 事实/问题 finding（去重 + 生命周期）；
- :mod:`hornwork.scan.cve`       NVD/OVAL 导入、CPE 映射、Debian 版本区间匹配、置信度；
- :mod:`hornwork.scan.diff`      快照四态差异（new/fixed/persisting/regressed）；
- :mod:`hornwork.scan.coverage`  资产 × 检查域加权覆盖率与未覆盖清单；
- :mod:`hornwork.scan.report`    HTML/JSON 报告（证据链可解释）；
- :mod:`hornwork.scan.api`       Web 只读查询门面；
- :mod:`hornwork.scan.runner`    一次扫描运行的编排器（闸门→引擎→归一→匹配→快照→报告）。

导入期不访问数据库、不执行外部命令（Windows 开发机可安全 import）。子模块采用**惰性导入**：
直接 ``from hornwork.scan import store`` 可用，``import hornwork.scan`` 不会连锁导入可选依赖。
"""

from __future__ import annotations

_SUBMODULES = {
    "store", "assets", "scheduler", "task", "engines", "normalize",
    "cve", "diff", "coverage", "report", "api", "runner",
}

__all__ = sorted(_SUBMODULES)


def __getattr__(name: str):  # pragma: no cover - 惰性导入的薄封装
    """按需导入子模块（避免并行开发期一个子模块出错导致整包不可 import）。"""
    if name in _SUBMODULES:
        import importlib

        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
