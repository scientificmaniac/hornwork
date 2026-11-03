"""认证模块：三因子认证子系统（口令 + TOTP + 人脸模板保护）。

实现范围与边界见 docs/authentication.md。
实现边界（本项目裁剪后的口径）：
- 自研：口令策略/PHC 解析/渐进迁移、RFC 4226/6238 TOTP、会话令牌、风险评分、
  限流锁定、审计哈希链、状态机、人脸模板可撤销变换 + AEAD 封装。
- 复用：`argon2-cffi`（Argon2id 原语）、`cryptography`（AES-GCM/HKDF/HMAC 原语）。
- 不实现：WebAuthn、PAM、InsightFace 模型推理、活体检测、
  浏览器登录页。人脸嵌入走可插拔接口（向量文件 / 轻量图像描述子 / 远程服务）。
"""

from __future__ import annotations

__all__ = ["crypto", "db", "password", "totp", "session", "biometric",
           "risk", "ratelimit", "policy", "audit", "engine"]

MODULE = "hornwork-auth"
VERSION = "0.1.0"
