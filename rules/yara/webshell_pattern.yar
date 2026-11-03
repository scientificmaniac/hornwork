/*
  Hornwork 自研 YARA 规则：WebShell 特征
  覆盖 PHP/JSP/ASP 等一句话木马的典型危险函数 + 超全局变量组合。
  命中阈值：出现任意一条危险调用即告警（演示环境误报可接受），level 由 severity 决定。
*/
rule webshell_pattern
{
    meta:
        description = "Common webshell dangerous function patterns (PHP/JSP/ASP)"
        attack = "T1505.003"
        severity = 85
        source = "hornwork-self"
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"

    strings:
        $w1 = "eval($_POST" ascii nocase
        $w2 = "eval($_GET" ascii nocase
        $w3 = "eval($_REQUEST" ascii nocase
        $w4 = "eval($_COOKIE" ascii nocase
        $w5 = "assert($_POST" ascii nocase
        $w6 = "assert($_REQUEST" ascii nocase
        $w7 = "system($_GET" ascii nocase
        $w8 = "system($_POST" ascii nocase
        $w9 = "passthru($_REQUEST" ascii nocase
        $w10 = "shell_exec($_POST" ascii nocase
        $w11 = "Runtime.getRuntime().exec" ascii
        $w12 = "ProcessBuilder(" ascii
        $w13 = "Request.Item[" ascii
        $w14 = "eval(base64_decode(" ascii nocase

    condition:
        filesize < 1MB and any of them
}
