"""扫描模块 CVE 子包：NVD/OVAL 导入 → CPE 映射 → Debian 版本区间匹配 → 置信度与证据。

子模块：

- :mod:`hornwork.scan.cve.feed`    NVD JSON 2.0 流式导入、Ubuntu OVAL 导入、缓存统计；
- :mod:`hornwork.scan.cve.version` Debian 版本比较/区间判定的薄包装（复用靶场模块比较器）；
- :mod:`hornwork.scan.cve.cmap`    CPE 2.3 解析与"本地组件名 ↔ CPE 前缀"映射表；
- :mod:`hornwork.scan.cve.matcher` 三层收敛匹配（OVAL 包级 → CPE 粗筛 → 区间精判）。

对外契约（runner 按此调用）::

    from hornwork.scan.cve import feed, matcher

    feed.import_nvd(store, paths, source="nvd")
    feed.import_oval(store, path, release="noble")
    matcher.match_facts(store, cfg, facts, archive_map)

导入期不读文件、不连库，Windows 开发机可安全 import。
"""

from __future__ import annotations

from . import cmap, feed, matcher, version

__all__ = ["feed", "version", "cmap", "matcher"]
